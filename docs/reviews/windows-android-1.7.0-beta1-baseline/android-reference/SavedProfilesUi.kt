package com.whitedns.vpn

import android.app.Activity
import android.content.res.ColorStateList
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.text.TextUtils
import android.view.ContextThemeWrapper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.annotation.DrawableRes
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.annotation.StringRes
import androidx.appcompat.widget.PopupMenu
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import java.text.DateFormat

internal data class SavedProfilesActions(
    val addSubscription: () -> Unit,
    val selectSubscription: (String) -> Unit,
    val connections: (String) -> Unit,
    val subscriptionOptions: (UserSubscription) -> List<Pair<Int, () -> Unit>>,
    val refreshBuiltIn: (String) -> Unit,
    val selectLocation: () -> Unit,
    val busy: () -> Boolean = { false },
)

/* Hallmark · pre-emit critique: P5 H5 E4 S5 R5 V4 */
/* Hallmark · genre: modern-minimal · macrostructure: Workbench · design-system: design.md · designed-as-app */
/** One destination for subscriptions and standalone engine profiles; creation never connects. */
internal class SavedProfilesUi(private val activity: Activity, private val engines: EngineProfilesUi,
    private val actions: SavedProfilesActions) {
    private val style = EngineFormStyle(activity)
    private val palette get() = style.palette
    private val SURFACE get() = palette.surface
    private val BACKGROUND get() = palette.background
    private val TEXT_PRIMARY get() = palette.textPrimary
    private val TEXT_SECONDARY get() = palette.textSecondary
    private val TEAL get() = palette.teal
    private val OUTLINE get() = palette.outline
    private val ERROR get() = palette.red
    private val subscriptions = UserSubscriptionManager(activity)
    private val store = SubscriptionStore(activity)
    private val engineStore = EngineProfileStore(activity)
    private lateinit var list: LinearLayout
    val view: View = build()
    private fun dp(value: Int) = style.dp(value)
    private fun build(): View = with(activity) {
        val scroll = ScrollView(this).apply {
            isFillViewport = true
            // Keep scrolled profile text outside the status-bar/display-cutout inset.
            clipToPadding = true
            setBackgroundColor(withAlpha(BACKGROUND, 0))
        }
        ViewCompat.setOnApplyWindowInsetsListener(scroll) { view, insets ->
            val topInset = insets.getInsets(
                WindowInsetsCompat.Type.statusBars() or WindowInsetsCompat.Type.displayCutout(),
            ).top
            view.setPadding(view.paddingLeft, topInset, view.paddingRight, view.paddingBottom)
            insets
        }
        val content = MaxWidthLinearLayout(this).apply {
            maxWidthPx = dp(520)
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(34), dp(24), dp(40))
        }
        val subscriptionsHeaderCopy = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutDirection = View.LAYOUT_DIRECTION_LOCALE
            addView(TextView(activity).apply {
                setText(R.string.subscriptions_title)
                ViewCompat.setAccessibilityHeading(this, true)
                textSize = 28f
                typeface = WhiteDnsDisplayTypeface
                setTextColor(TEXT_PRIMARY)
                includeFontPadding = false
                gravity = Gravity.START
            })
            addView(
                TextView(activity).apply {
                    setText(R.string.subscriptions_description)
                    textSize = 14f
                    typeface = WhiteDnsBodyTypeface
                    setTextColor(TEXT_SECONDARY)
                    includeFontPadding = false
                    gravity = Gravity.START
                },
                LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(4) },
            )
        }
        val addSubscriptionButton = MaterialButton(this).apply {
            setText(R.string.profile_add)
            layoutDirection = View.LAYOUT_DIRECTION_LOCALE
            textDirection = View.TEXT_DIRECTION_LOCALE
            setAllCaps(false)
            textSize = 12f
            typeface = WhiteDnsBodyBoldTypeface
            isSingleLine = true
            setPadding(dp(8), 0, dp(8), 0)
            minWidth = 0
            insetTop = 0
            insetBottom = 0
            cornerRadius = dp(8)
            backgroundTintList = ColorStateList.valueOf(SURFACE)
            strokeWidth = dp(1)
            strokeColor = ColorStateList.valueOf(TEAL)
            rippleColor = ColorStateList.valueOf(withAlpha(TEAL, 24))
            setTextColor(TEAL)
            tag = "add-profile"
            setOnClickListener { showAddProfileDialog() }
        }
        val compactHeader = resources.configuration.screenWidthDp < 360
        content.addView(LinearLayout(this).apply {
            orientation = if (compactHeader) LinearLayout.VERTICAL else LinearLayout.HORIZONTAL
            layoutDirection = View.LAYOUT_DIRECTION_LOCALE
            gravity = if (compactHeader) Gravity.START else Gravity.CENTER_VERTICAL
            if (compactHeader) {
                addView(
                    subscriptionsHeaderCopy,
                    LinearLayout.LayoutParams(-1, -2),
                )
                addView(
                    addSubscriptionButton,
                    LinearLayout.LayoutParams(-2, dp(44)).apply { topMargin = dp(16) },
                )
            } else {
                addView(
                    subscriptionsHeaderCopy,
                    LinearLayout.LayoutParams(0, -2, 1f),
                )
                addView(
                    addSubscriptionButton,
                    LinearLayout.LayoutParams(dp(84), dp(44)).apply { marginStart = dp(16) },
                )
            }
        })
        list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; tag = "profiles-list" }
        content.addView(list, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(24) })
        scroll.tag = "profiles-screen"
        scroll.addView(content, ViewGroup.LayoutParams(-1, -2))
        scroll
    }
    private fun showAddProfileDialog() {
        if (actions.busy()) return
        MaterialAlertDialogBuilder(activity).setTitle(R.string.profile_add_title)
            .setWhiteDnsItems(listOf(activity.getString(R.string.profile_subscription_add)) + EngineKind.selectable.map { it.title }) { _, which ->
                if (which == 0) actions.addSubscription() else engines.addProfile(EngineKind.selectable[which - 1])
            }.setNegativeButton(R.string.split_tunnel_cancel, null).showWhiteDnsEngineDialog()
    }
    fun render() {
        list.removeAllViews()
        val selectedEngine = engineStore.selectedEngineId()
        val selectedSubscription = store.readSelectedSubscriptionId()
        fun count(n: Int) = activity.resources.getQuantityString(R.plurals.connection_count, n, n)
        fun add(card: View) {
            list.addView(card, LinearLayout.LayoutParams(-1, -2).apply { if (list.childCount > 0) topMargin = dp(8) })
        }
        fun subscriptionActions(id: String, options: List<Pair<Int, () -> Unit>>): List<Pair<Int, () -> Unit>> {
            val location = if (selectedEngine == null && selectedSubscription == id)
                listOf(R.string.location_selector_title to actions.selectLocation) else emptyList()
            return listOf(R.string.subscription_action_select to { if (!actions.busy()) actions.selectSubscription(id) }) + options + location
        }
        SubscriptionStore.BUILT_IN_SUBSCRIPTION_IDS.forEach { id ->
            add(profileCard(
                cardId = "subscription:" + id,
                title = activity.getString(if (id == SubscriptionStore.PUBLIC_SUBSCRIPTION_ID)
                    R.string.subscription_public_name else R.string.subscription_private_name),
                kind = activity.getString(R.string.profile_subscription_type),
                detail = activity.getString(R.string.subscription_builtin_detail, count(store.readCatalog(id)?.profiles?.size ?: 0)),
                selected = selectedEngine == null && selectedSubscription == id,
                error = "", primaryLabel = R.string.profile_connections,
                onTestConnections = { if (!actions.busy()) actions.connections(id) },
                actions = subscriptionActions(id, listOf(R.string.subscription_action_refresh to { actions.refreshBuiltIn(id) })),
            ))
        }
        subscriptions.list().forEach { item ->
            val updated = item.updatedAt.takeIf { it > 0 }?.let {
                DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(it)
            } ?: activity.getString(R.string.subscription_never_updated)
            add(profileCard(
                cardId = "subscription:" + item.id, title = item.name, kind = activity.getString(R.string.profile_subscription_type),
                detail = activity.getString(R.string.subscription_detail, item.format.label, count(item.connectionCount), updated),
                selected = selectedEngine == null && selectedSubscription == item.id,
                error = if (item.lastError.isBlank()) "" else activity.getString(R.string.subscription_operation_failed),
                primaryLabel = R.string.profile_connections, onTestConnections = { if (!actions.busy()) actions.connections(item.id) },
                actions = subscriptionActions(item.id, actions.subscriptionOptions(item)),
            ))
        }
        val profiles = try { engineStore.profiles() } catch (_: Exception) {
            list.addView(style.detail(activity.getString(R.string.engine_missing_profile))); emptyList()
        }
        profiles.forEach { profile ->
            val unavailable = engines.unavailableReason(profile)
            add(profileCard(
                cardId = "engine:" + profile.id, title = profile.name, kind = profile.kind.title,
                detail = activity.getString(if (profile.kind.socks) R.string.profile_tcp_route else R.string.profile_vpn_route),
                selected = selectedEngine == profile.id,
                error = unavailable?.let(activity::getString).orEmpty(), primaryLabel = R.string.subscription_action_test,
                onTestConnections = { engines.showTests(profile) }, primaryEnabled = unavailable == null,
                actions = listOf(
                    R.string.subscription_action_select to { engines.select(profile) },
                    R.string.engine_edit to { engines.editProfile(profile) },
                    R.string.engine_delete to { engines.deleteProfile(profile) },
                ),
            ))
        }
        if (selectedEngine != null && profiles.none { it.id == selectedEngine }) {
            list.addView(style.detail(activity.getString(R.string.engine_missing_profile)))
        }
    }
    private fun profileCard(
        cardId: String,
        kind: String,
        primaryLabel: Int,
        title: String,
        detail: String,
        selected: Boolean,
        error: String,
        onTestConnections: () -> Unit,
        primaryEnabled: Boolean = true,
        actions: List<Pair<Int, () -> Unit>>,
    ): View = with(activity) { LinearLayout(this).apply {
        tag = "saved-profile:" + cardId
        orientation = LinearLayout.VERTICAL
        layoutDirection = View.LAYOUT_DIRECTION_LOCALE
        gravity = Gravity.START
        minimumHeight = dp(112)
        setPaddingRelative(dp(16), dp(12), dp(16), dp(12))
        elevation = 0f
        val selectAction = actions.firstOrNull { it.first == R.string.subscription_action_select }
        val overflowActions = actions.filterNot { it.first == R.string.subscription_action_select }
        val canSelect = selectAction != null && !selected
        isClickable = canSelect
        isFocusable = canSelect
        contentDescription = "$title, ${getString(
            if (selected) R.string.subscription_selected_badge else R.string.subscription_action_select,
        )}"
        background = if (selected) {
            glassSurfaceDrawable(radiusDp = 12, highlighted = true)
        } else {
            RippleDrawable(
                ColorStateList.valueOf(withAlpha(TEAL, 28)),
                glassSurfaceDrawable(radiusDp = 12),
                null,
            )
        }
        clipToOutline = true
        if (canSelect) {
            setOnClickListener { selectAction?.second?.invoke() }
        }

        addView(
            LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutDirection = View.LAYOUT_DIRECTION_LOCALE
                gravity = Gravity.CENTER_VERTICAL
                addView(
                    TextView(activity).apply {
                        text = title
                        textSize = 16f
                        typeface = WhiteDnsBodyBoldTypeface
                        setTextColor(TEXT_PRIMARY)
                        includeFontPadding = false
                        maxLines = 1
                        ellipsize = TextUtils.TruncateAt.END
                        layoutDirection = View.LAYOUT_DIRECTION_LOCALE
                        textDirection = View.TEXT_DIRECTION_FIRST_STRONG
                        gravity = Gravity.START
                    },
                    LinearLayout.LayoutParams(0, -2, 1f),
                )
                if (selected) addView(
                    TextView(activity).apply {
                        tag = "selected-profile-badge"
                        setText(R.string.subscription_selected_badge)
                        textSize = 12f
                        typeface = WhiteDnsBodyBoldTypeface
                        setTextColor(TEAL)
                        includeFontPadding = false
                        gravity = Gravity.CENTER
                        isSingleLine = true
                        setPaddingRelative(dp(8), dp(4), dp(8), dp(4))
                        background = GradientDrawable().apply {
                            shape = GradientDrawable.RECTANGLE
                            cornerRadius = dp(12).toFloat()
                            setColor(SURFACE)
                            setStroke(dp(1), withAlpha(TEAL, 92))
                        }
                    },
                    LinearLayout.LayoutParams(-2, -2).apply { marginStart = dp(12) },
                )
            },
            LinearLayout.LayoutParams(-1, -2),
        )
        addView(TextView(activity).apply {
            text = kind + if (detail.isBlank()) "" else " · " + detail
            textSize = 12f
            typeface = WhiteDnsBodyTypeface
            setTextColor(TEXT_SECONDARY)
            includeFontPadding = false
            maxLines = 2
            ellipsize = TextUtils.TruncateAt.END
            layoutDirection = View.LAYOUT_DIRECTION_LOCALE
            textDirection = View.TEXT_DIRECTION_FIRST_STRONG
            gravity = Gravity.START
        }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(4) })
        if (error.isNotBlank()) addView(TextView(activity).apply {
            text = error
            textSize = 12f
            typeface = WhiteDnsBodyBoldTypeface
            setTextColor(ERROR)
            layoutDirection = View.LAYOUT_DIRECTION_LOCALE
            textDirection = View.TEXT_DIRECTION_FIRST_STRONG
            gravity = Gravity.START
        }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })

        fun actionButton(
            @StringRes labelRes: Int,
            @DrawableRes iconRes: Int,
            accent: Boolean,
            action: (View) -> Unit,
        ): MaterialButton = MaterialButton(activity).apply {
            setText(labelRes)
            if (resources.configuration.screenWidthDp >= 360) setIconResource(iconRes)
            iconTint = ColorStateList.valueOf(if (accent) TEAL else TEXT_SECONDARY)
            iconSize = dp(18)
            iconPadding = dp(8)
            iconGravity = MaterialButton.ICON_GRAVITY_TEXT_START
            setAllCaps(false)
            isSingleLine = true
            ellipsize = TextUtils.TruncateAt.END
            textSize = 14f
            typeface = WhiteDnsBodyBoldTypeface
            minWidth = 0
            minimumWidth = 0
            minHeight = dp(48)
            minimumHeight = dp(48)
            insetTop = 0
            insetBottom = 0
            cornerRadius = dp(8)
            setPaddingRelative(dp(12), 0, dp(12), 0)
            backgroundTintList = ColorStateList.valueOf(SURFACE)
            strokeWidth = dp(1)
            strokeColor = ColorStateList.valueOf(if (accent) withAlpha(TEAL, 150) else OUTLINE)
            rippleColor = ColorStateList.valueOf(withAlpha(TEAL, 26))
            setTextColor(if (accent) TEAL else TEXT_PRIMARY)
            setOnClickListener(action)
        }

        addView(
            LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutDirection = View.LAYOUT_DIRECTION_LOCALE
                addView(
                    actionButton(
                        labelRes = primaryLabel,
                        iconRes = R.drawable.ic_connection_test,
                        accent = true,
                    ) { onTestConnections() }.apply {
                        tag = "profile-primary:" + cardId
                        isEnabled = primaryEnabled
                        if (!primaryEnabled) {
                            setTextColor(TEXT_SECONDARY)
                            iconTint = ColorStateList.valueOf(TEXT_SECONDARY)
                            strokeColor = ColorStateList.valueOf(OUTLINE)
                        }
                    },
                    LinearLayout.LayoutParams(0, dp(48), 1f),
                )
                addView(
                    actionButton(
                        labelRes = R.string.subscription_action_options,
                        iconRes = R.drawable.ic_more_vert,
                        accent = false,
                    ) { view ->
                        whiteDnsPopupMenu(view).apply {
                            overflowActions.forEachIndexed { index, (labelRes, _) ->
                                menu.add(0, index, index, labelRes)
                            }
                            setOnMenuItemClickListener { item ->
                                overflowActions[item.itemId].second()
                                true
                            }
                        }.show()
                    },
                    LinearLayout.LayoutParams(0, dp(48), 1f).apply { marginStart = dp(8) },
                )
            },
            LinearLayout.LayoutParams(-1, dp(48)).apply { topMargin = dp(12) },
        )
    } }

    private fun glassSurfaceDrawable(radiusDp: Int, highlighted: Boolean = false) = GradientDrawable().apply {
        cornerRadius = dp(radiusDp).toFloat()
        setColor(SURFACE)
        if (highlighted) setStroke(dp(1), withAlpha(TEAL, 170))
    }
    private fun whiteDnsPopupMenu(anchor: View) = PopupMenu(ContextThemeWrapper(activity, R.style.WhiteDnsPopupTheme), anchor)
    private fun withAlpha(color: Int, alpha: Int) = (color and 0x00FFFFFF) or (alpha.coerceIn(0, 255) shl 24)
}
