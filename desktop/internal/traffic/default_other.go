//go:build !darwin && !linux && !windows

package traffic

func DefaultSampler() Sampler {
	return UnavailableSampler{Message: "traffic monitor is not available on this platform"}
}
