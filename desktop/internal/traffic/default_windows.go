//go:build windows

package traffic

func DefaultSampler() Sampler {
	return WindowsProcessIOSampler{}
}
