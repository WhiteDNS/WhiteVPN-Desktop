package com.whitedns.vpn

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.text.InputFilter
import android.view.Gravity
import android.view.WindowManager
import com.google.android.material.textfield.MaterialAutoCompleteTextView
import android.security.KeyChain
import android.text.InputType
import android.view.View
import android.widget.*
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputLayout
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.*

internal data class EngineField(val key: String, val label: Int, val default: String = "", val secret: Boolean = false,
    val multiline: Boolean = false, val options: List<String> = emptyList())

internal object EngineFields {
    fun fields(kind: EngineKind, values: Map<String, String>): List<EngineField> {
        fun f(key: String, label: Int, default: String = "", secret: Boolean = false, multiline: Boolean = false) = EngineField(key, label, default, secret, multiline)
        fun pick(key: String, label: Int, default: String, vararg values: String) = EngineField(key, label, default, options = values.toList())
        return when (kind) {
            EngineKind.SSH -> listOf(f("host", R.string.engine_host), f("port", R.string.engine_port, "22"), f("username", R.string.engine_username),
                pick("authType", R.string.engine_auth, "password", "password", "key")) +
                if (values["authType"] == "key") listOf(f("privateKey", R.string.engine_private_key, secret = true, multiline = true), f("keyPassphrase", R.string.engine_key_passphrase, secret = true))
                else listOf(f("password", R.string.engine_password, secret = true))
            EngineKind.PSIPHON -> listOf(pick("mode", R.string.engine_psiphon_mode, "auto", "auto", "cdn", "direct"), EngineField("country", R.string.engine_country, options = listOf("") + PsiphonRegions.knownCodes)) +
                if (values["mode"] == "direct") emptyList() else listOf(f("cdnIps", R.string.engine_cdn_ips), f("cdnSni", R.string.engine_cdn_sni))
            EngineKind.TOR -> listOf(pick("bridgeMode", R.string.engine_bridge_mode, "default", "none", "default", "custom")) +
                if (values["bridgeMode"] == "none") emptyList() else listOf(pick("transport", R.string.engine_transport, "obfs4", "obfs4", "snowflake", "conjure")) +
                    if (values["bridgeMode"] == "custom") listOf(f("bridges", R.string.engine_bridges, multiline = true)) else emptyList()
            EngineKind.DNS -> listOf(pick("engine", R.string.engine_dns_engine, "dnstt", "dnstt", "vaydns", "masterdns")) +
                if (values["engine"] == "masterdns") listOf(f("domains", R.string.engine_domains), f("resolvers", R.string.engine_resolvers, multiline = true),
                    pick("encryptionMethod", R.string.engine_encryption, "2", "0", "1", "2", "3", "4", "5"), f("encryptionKey", R.string.engine_encryption_key, secret = true))
                else listOf(f("domain", R.string.engine_domain), f("publicKey", R.string.engine_public_key),
                    pick("dnsTransport", R.string.engine_transport, "udp", "udp", "tcp", "dot", "doh")) +
                    (if (values["dnsTransport"] == "doh") listOf(f("dohUrl", R.string.engine_doh_url, "https://dns.google/dns-query")) else listOf(f("resolvers", R.string.engine_resolvers, "8.8.8.8", multiline = true))) +
                    listOf(f("socksUser", R.string.engine_socks_user), f("socksPass", R.string.engine_socks_password, secret = true))
            EngineKind.OPENCONNECT -> emptyList()
            EngineKind.AMNEZIAWG -> listOf(f("config", R.string.engine_amnezia_config, secret = true, multiline = true))
            EngineKind.IKEV2 -> listOf(f("server", R.string.engine_gateway), f("localId", R.string.engine_local_id),
                pick("authType", R.string.engine_auth, "eap_mschapv2", "eap_mschapv2", "psk", "certificate"), f("caCertPem", R.string.engine_ca_certificate, multiline = true)) + when (values["authType"]) {
                    "psk" -> listOf(f("psk", R.string.engine_psk, secret = true))
                    "certificate" -> listOf(f("userCertAlias", R.string.engine_certificate_alias))
                    else -> listOf(f("username", R.string.engine_username), f("password", R.string.engine_password, secret = true))
                }
        }
    }
}

internal data class EngineEditorState(val existing: EngineProfile?, val kind: EngineKind,
    val values: Map<String, String>, val name: String, val waitingForFile: Boolean)

internal class EngineProfilesUi(private val activity: Activity, private val scope: CoroutineScope,
    private val busy: () -> Boolean, private val onChanged: () -> Unit = {}, private val onSelected: () -> Unit) {
    private val store = EngineProfileStore(activity)
    private val style = EngineFormStyle(activity)
    private var editorState: (() -> EngineEditorState)? = null
    private var editorDialog: androidx.appcompat.app.AlertDialog? = null
    private var fileReceiver: ((Uri) -> Unit)? = null
    private var waitingForFile = false
    private var fileJob: Job? = null
    fun retainEditor(): EngineEditorState? = editorState?.invoke()
    fun restoreEditor(state: EngineEditorState) = edit(state.existing, state.kind, state)
    fun dispose() { fileJob?.cancel(); editorDialog?.dismiss(); editorState = null; fileReceiver = null }
    fun handleActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode != REQUEST_AMNEZIA_FILE) return false
        val receiver = fileReceiver.takeIf { waitingForFile }
        waitingForFile = false
        if (resultCode == Activity.RESULT_OK) {
            val uri = data?.data
            if (receiver != null && uri != null && uri.scheme == "content") receiver(uri)
            else Toast.makeText(activity, R.string.engine_import_failed, Toast.LENGTH_LONG).show()
        }
        return true
    }
    companion object { const val REQUEST_AMNEZIA_FILE = 120 }

    private var observers: List<Job> = emptyList()
    private var promptDialog: androidx.appcompat.app.AlertDialog? = null
    private var promptSource: String? = null
    fun addProfile(kind: EngineKind) {
        if (busy() || kind !in EngineKind.selectable) return
        edit(null, kind)
    }
    fun editProfile(profile: EngineProfile) {
        if (busy()) return
        if (profile.kind == EngineKind.OPENCONNECT) Toast.makeText(activity, R.string.engine_retired, Toast.LENGTH_LONG).show()
        else edit(profile, profile.kind)
    }
    fun deleteProfile(profile: EngineProfile) {
        if (busy()) return
        MaterialAlertDialogBuilder(activity).setTitle(R.string.engine_delete).setMessage(profile.name)
            .setPositiveButton(R.string.engine_delete) { _, _ ->
                if (VpnRuntimeStateStore.readActiveConnectionFingerprint(activity) == profile.id && VpnRuntimeStateStore.read(activity) != VpnState.Stopped) {
                    Toast.makeText(activity, R.string.engine_stop_before_edit, Toast.LENGTH_LONG).show()
                } else { store.delete(profile.id); onChanged() }
            }.setNegativeButton(R.string.split_tunnel_cancel, null).showWhiteDnsEngineDialog()
    }
    fun showTests(profile: EngineProfile) {
        if (busy()) return
        MaterialAlertDialogBuilder(activity).setTitle(profile.name)
            .setWhiteDnsItems(listOf(activity.getString(R.string.engine_test), activity.getString(R.string.engine_speed_test))) { _, which -> test(profile, which == 1) }
            .setNegativeButton(R.string.split_tunnel_cancel, null).showWhiteDnsEngineDialog()
    }
    fun unavailableReason(profile: EngineProfile): Int? {
        val availability = EngineNativeAvailability.check(activity, profile)
        if (availability !is EngineAvailability.Unavailable) return null
        return when (availability.reason) {
            EngineAvailability.Reason.RETIRED -> R.string.engine_retired
            EngineAvailability.Reason.ANDROID_VERSION -> R.string.engine_android_version
            EngineAvailability.Reason.IPSEC_UNSUPPORTED -> R.string.engine_ipsec_unavailable
            EngineAvailability.Reason.TOR_TRANSPORT, EngineAvailability.Reason.TOR_ASSETS -> R.string.engine_transport_missing
            else -> R.string.engine_native_missing
        }
    }
    fun select(profile: EngineProfile) {
        if (busy()) return
        unavailableReason(profile)?.let { reason ->
            MaterialAlertDialogBuilder(activity).setTitle(profile.kind.title).setMessage(reason)
                .setPositiveButton(android.R.string.ok, null).showWhiteDnsEngineDialog()
            return
        }
        if (!profile.kind.socks && !ConnectionModePolicy.shouldStartTun(ConnectionModePreferenceStore(activity).read(),
                VpnRuntimeStateStore.readAlwaysOn(activity), VpnRuntimeStateStore.readLockdown(activity))) {
            MaterialAlertDialogBuilder(activity).setTitle(profile.kind.title).setMessage(R.string.engine_choose_vpn_access)
                .setPositiveButton(android.R.string.ok, null).showWhiteDnsEngineDialog()
            return
        }
        MaterialAlertDialogBuilder(activity).setTitle(profile.name)
            .setMessage(activity.getString(if (profile.kind.socks) R.string.engine_tcp_features else if (profile.kind == EngineKind.IKEV2) R.string.engine_ikev2_features else R.string.engine_amnezia_features) +
                if (profile.kind == EngineKind.AMNEZIAWG) "\n\n" + AmneziaProfile.publicSummary(AmneziaProfile.parse(profile.value("config"))) else "")
            .setPositiveButton(R.string.engine_select) { _, _ -> store.selectEngine(profile.id); onSelected() }
            .setNegativeButton(R.string.split_tunnel_cancel, null).showWhiteDnsEngineDialog()
    }
    private fun edit(existing: EngineProfile?, kind: EngineKind, restored: EngineEditorState? = null) {
        if (existing != null && VpnRuntimeStateStore.readActiveConnectionFingerprint(activity) == existing.id && VpnRuntimeStateStore.read(activity) != VpnState.Stopped) {
            Toast.makeText(activity, R.string.engine_stop_before_edit, Toast.LENGTH_LONG).show(); return
        }
        editorDialog?.dismiss()
        val values = (restored?.values ?: existing?.config?.settings).orEmpty().toMutableMap()
        val column = style.column()
        if (kind == EngineKind.AMNEZIAWG) column.addView(style.detail(activity.getString(R.string.engine_amnezia_instructions)))
        if (kind == EngineKind.DNS) column.addView(style.detail(activity.getString(R.string.engine_dns_explanation)))
        val name = input(column, EngineField("name", R.string.engine_name), restored?.name ?: existing?.name.orEmpty())
        val importStatus = style.detail("").apply { visibility = View.GONE; tag = "engine-import-status" }
        val form = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }; column.addView(form)
        val controls = mutableMapOf<String, () -> String>()
        val inputs = mutableMapOf<String, TextInputEditText>()
        fun collect() { controls.forEach { (key, value) -> values[key] = value() } }
        fun render(focusKey: String? = null) {
            form.removeAllViews(); controls.clear(); inputs.clear()
            EngineFields.fields(kind, values).forEach { original ->
                val field = if (kind == EngineKind.PSIPHON && original.key == "country")
                    original.copy(options = PsiphonRegions.options(activity, values["country"].orEmpty())) else original
                val initial = (values[field.key] ?: field.default).let {
                    if (field.key == "country") it.trim().uppercase(java.util.Locale.US) else it
                }
                if (field.options.isEmpty()) {
                    val edit = input(form, field, initial); inputs[field.key] = edit
                    if (field.key == "userCertAlias") {
                        edit.inputType = InputType.TYPE_NULL
                        edit.isCursorVisible = false
                        edit.showSoftInputOnFocus = false
                        edit.setOnClickListener { KeyChain.choosePrivateKeyAlias(activity, { alias -> activity.runOnUiThread {
                            if (alias != null && edit.isAttachedToWindow) edit.setText(alias)
                        } }, null, null, null, -1, initial.takeIf { it.isNotBlank() }) }
                    }
                    controls[field.key] = { edit.text?.toString().orEmpty() }
                } else {
                    val layout = style.field(activity.getString(field.label)).apply { endIconMode = TextInputLayout.END_ICON_DROPDOWN_MENU }
                    val picker = MaterialAutoCompleteTextView(activity).apply {
                        tag = field.key; inputType = InputType.TYPE_NULL; background = null
                        textSize = 14f; typeface = WhiteDnsBodyTypeface; setTextColor(style.palette.textPrimary)
                        setPaddingRelative(style.dp(16), style.dp(12), style.dp(16), style.dp(12))
                        setAdapter(style.adapter(field.options.map { optionLabel(field, it) }, dropdown = true))
                        setText(optionLabel(field, initial.takeIf { it in field.options } ?: field.default), false)
                        setDropDownBackgroundDrawable(android.graphics.drawable.ColorDrawable(style.palette.surface))
                        setOnKeyListener { _, code, event ->
                            if ((code == android.view.KeyEvent.KEYCODE_DPAD_CENTER || code == android.view.KeyEvent.KEYCODE_ENTER) &&
                                event.action == android.view.KeyEvent.ACTION_UP) { showDropDown(); true } else false
                        }
                    }
                    layout.addView(picker); form.addView(layout)
                    var selected = initial.takeIf { it in field.options } ?: field.default
                    controls[field.key] = { selected }
                    picker.setOnItemClickListener { _, _, position, _ ->
                        val choice = field.options[position]
                        if (selected != choice) { collect(); selected = choice; values[field.key] = choice; render(field.key) }
                    }
                    if (field.key == focusKey) picker.requestFocus()
                }
            }
        }
        render()
        val dialog = MaterialAlertDialogBuilder(activity).setTitle(kind.title).setView(style.scroll(column))
            .setPositiveButton(R.string.engine_save, null).setNegativeButton(R.string.split_tunnel_cancel, null).create()
        editorDialog = dialog
        if (kind == EngineKind.AMNEZIAWG) {
            fun applyImport(config: String) {
                if (!dialog.isShowing) return
                inputs["config"]?.setText(config)
                if (name.text.isNullOrBlank()) name.setText(kind.title)
                importStatus.text = activity.getString(R.string.engine_import_ready)
                importStatus.setTextColor(style.palette.teal); importStatus.visibility = View.VISIBLE
            }
            fileReceiver = { uri ->
                fileJob?.cancel()
                fileJob = scope.launch {
                    try {
                        val config = withContext(Dispatchers.IO) {
                            activity.contentResolver.openInputStream(uri)?.use(AmneziaConfigImport::read)
                                ?: throw IllegalArgumentException("Document unavailable")
                        }
                        applyImport(config)
                    } catch (_: CancellationException) { /* Dismissed editor never receives a late import. */ }
                    catch (_: Exception) {
                        if (dialog.isShowing) {
                            importStatus.text = activity.getString(R.string.engine_import_failed)
                            importStatus.setTextColor(style.palette.red); importStatus.visibility = View.VISIBLE
                        }
                    }
                }
            }
            val imports = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
            imports.addView(style.button(R.string.engine_import_file) {
                if (!waitingForFile) {
                    try {
                        waitingForFile = true
                        activity.startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                            addCategory(Intent.CATEGORY_OPENABLE); type = "*/*"
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }, REQUEST_AMNEZIA_FILE)
                    } catch (_: Exception) {
                        waitingForFile = false
                        Toast.makeText(activity, R.string.engine_file_picker_unavailable, Toast.LENGTH_LONG).show()
                    }
                }
            })
            imports.addView(style.button(R.string.engine_import_link) { importLink { config -> fileJob?.cancel(); applyImport(config) } })
            imports.addView(importStatus)
            column.addView(imports, column.indexOfChild(form))
        }
        waitingForFile = restored?.waitingForFile ?: false
        editorState = { collect(); EngineEditorState(existing, kind, values.toMap(), name.text?.toString().orEmpty(), waitingForFile) }
        dialog.setOnDismissListener {
            if (editorDialog === dialog) {
                fileJob?.cancel(); fileJob = null; fileReceiver = null; waitingForFile = false
                editorDialog = null; editorState = null
            }
        }
        dialog.showWhiteDnsEngineDialog()
        dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            collect()
            // Hidden subtype fields are discarded, including previous authentication credentials.
            val settings = EngineFields.fields(kind, values).associate { it.key to (values[it.key] ?: it.default) }.toMutableMap()
            try {
                if (kind == EngineKind.AMNEZIAWG) settings["config"] = AmneziaConfigImport.decode(settings["config"].orEmpty())
                val profile = EngineProfile(existing?.id ?: java.util.UUID.randomUUID().toString(), name.text?.toString()?.trim().orEmpty(), kind, EngineConfig.of(kind, settings))
                store.save(profile); dialog.dismiss(); onChanged()
            } catch (_: Exception) { error() }
        }
    }
    private fun importLink(apply: (String) -> Unit) {
        val body = style.column()
        body.addView(style.detail(activity.getString(R.string.engine_import_link_hint)))
        val link = input(body, EngineField("vpnLink", R.string.engine_vpn_link, secret = true, multiline = true), "")
        // Material inserts an input FrameLayout between TextInputEditText and TextInputLayout.
        val layout = generateSequence(link.parent) { it.parent }.filterIsInstance<TextInputLayout>().first()
        val dialog = MaterialAlertDialogBuilder(activity).setTitle(R.string.engine_import_link).setView(style.scroll(body))
            .setPositiveButton(R.string.engine_import_apply, null).setNegativeButton(R.string.split_tunnel_cancel, null).create()
        dialog.showWhiteDnsEngineDialog()
        dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            try {
                val text = link.text?.toString().orEmpty().trim()
                require(text.startsWith("vpn://", ignoreCase = true))
                val config = AmneziaConfigImport.decode(text)
                apply(config); link.text?.clear(); dialog.dismiss()
            } catch (_: Exception) { layout.error = activity.getString(R.string.engine_import_failed) }
        }
    }
    private fun optionLabel(field: EngineField, value: String): String {
        if (field.key == "country") return if (value.isBlank()) activity.getString(R.string.engine_option_auto)
            else PsiphonRegions.name(value, activity.resources.configuration.locales[0])
        if (field.key == "encryptionMethod") return listOf(activity.getString(R.string.engine_option_plaintext), "XOR", "ChaCha20", "AES-128", "AES-192", "AES-256")[value.toInt()]
        val label = when (value) {
            "auto" -> R.string.engine_option_auto
            "cdn" -> R.string.engine_option_cdn
            "direct" -> R.string.engine_option_direct
            "none" -> R.string.engine_option_no_bridges
            "default" -> R.string.engine_option_default_bridges
            "custom" -> R.string.engine_option_custom_bridges
            "password" -> R.string.engine_password
            "key" -> R.string.engine_private_key
            "eap_mschapv2" -> R.string.engine_option_eap
            "psk" -> R.string.engine_psk
            "certificate" -> R.string.engine_option_certificate
            else -> null
        }
        return label?.let(activity::getString) ?: when (value) { "dnstt" -> "DNSTT"; "vaydns" -> "VayDNS"; "masterdns" -> "MasterDNS"; "udp" -> "UDP"; "tcp" -> "TCP"; "dot" -> "DoT"; "doh" -> "DoH"; else -> value }
    }
    private fun input(parent: LinearLayout, field: EngineField, value: String): TextInputEditText {
        val layout = style.field(activity.getString(field.label))
        val edit = TextInputEditText(activity).apply {
            tag = field.key; setText(value); isSingleLine = !field.multiline
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or
                (if (field.secret) InputType.TYPE_TEXT_VARIATION_PASSWORD else InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD) or
                (if (field.multiline) InputType.TYPE_TEXT_FLAG_MULTI_LINE else 0)
            textSize = 14f; typeface = WhiteDnsBodyTypeface; background = null
            setTextColor(style.palette.textPrimary); setHintTextColor(style.palette.textSecondary)
            setPaddingRelative(style.dp(16), style.dp(12), style.dp(16), style.dp(12))
            gravity = Gravity.TOP or Gravity.START
            if (field.multiline) { minLines = if (field.key == "config") 6 else 3; maxLines = 9 }
            filters = arrayOf(InputFilter.LengthFilter(if (field.key == "vpnLink" || field.key == "config") AmneziaConfigImport.MAX_INPUT_BYTES else if (field.key == "name") 100 else 65_536))
            // Draft credentials stay in memory, including while the system document picker is open.
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            if (field.key != "name") {
                // Keep the input and its container in the same layout direction so Material
                // reserves the eye icon's space on the correct side in both RTL and LTR.
                // Technical values align left-to-right while labels retain the locale's gravity.
                textDirection = View.TEXT_DIRECTION_LTR
                textAlignment = View.TEXT_ALIGNMENT_TEXT_START
            }
        }
        if (field.secret) layout.endIconMode = TextInputLayout.END_ICON_PASSWORD_TOGGLE
        layout.addView(edit); parent.addView(layout)
        return edit
    }
    private fun error() { Toast.makeText(activity, R.string.engine_invalid, Toast.LENGTH_LONG).show() }
    private fun test(profile: EngineProfile, speed: Boolean) {
        val state = VpnRuntimeStateStore.read(activity)
        if (state == VpnState.Starting || state == VpnState.Stopping) return
        if (profile.kind.socks && state == VpnState.Started) {
            if (VpnRuntimeStateStore.readActiveConnectionFingerprint(activity) == profile.id) {
                scope.launch { testResult { EngineProfileTester.activeSocks(activity, speed) } }
            } else Toast.makeText(activity, R.string.engine_stop_before_test, Toast.LENGTH_LONG).show()
        } else if (!profile.kind.socks) {
            if (state != VpnState.Started || VpnRuntimeStateStore.readActiveConnectionFingerprint(activity) != profile.id) {
                Toast.makeText(activity, R.string.engine_native_test_active, Toast.LENGTH_LONG).show(); return
            }
            scope.launch { testResult { EngineProfileTester.native(activity, speed) } }
        } else scope.launch { testResult { EngineProfileTester.isolated(activity, profile, speed) } }
    }
    private suspend fun testResult(test: suspend () -> String) {
        val dialog = MaterialAlertDialogBuilder(activity).setTitle(R.string.engine_test).setMessage(R.string.engine_testing)
            .setNegativeButton(R.string.split_tunnel_cancel, null).create()
        val job = scope.launch {
            val result = try { test() } catch (_: CancellationException) { return@launch } catch (_: Throwable) { activity.getString(R.string.engine_test_failed) }
            dialog.setMessage(result)
        }
        dialog.setOnDismissListener { job.cancel() }; dialog.showWhiteDnsEngineDialog()
    }
    fun observe() {
        if (observers.isNotEmpty()) return
        observers = listOf(
            scope.launch { EngineTrustPrompts.pending.collect { prompt ->
                if (prompt != null) trust(prompt.message, "ssh") { EngineTrustPrompts.answer(prompt, it) } else dismissPrompt("ssh")
            } },
        )
    }
    private fun trust(message: String, source: String, answer: (Boolean) -> Unit) {
        dismissPrompt(); promptSource = source
        promptDialog = MaterialAlertDialogBuilder(activity).setTitle(R.string.engine_trust).setMessage(message)
            .setPositiveButton(R.string.engine_trust_accept) { _, _ -> answer(true) }
            .setNegativeButton(R.string.split_tunnel_cancel) { _, _ -> answer(false) }
            .setOnCancelListener { answer(false) }.create().also { it.showWhiteDnsEngineDialog() }
    }
    private fun dismissPrompt(source: String? = null) {
        if (source != null && source != promptSource) return
        promptDialog?.dismiss(); promptDialog = null; promptSource = null
    }
    fun stopObserving() { observers.forEach { it.cancel() }; observers = emptyList(); dismissPrompt() }
}
