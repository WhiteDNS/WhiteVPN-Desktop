//go:build linux

package traffic

func DefaultSampler() Sampler {
	return NewLinuxSampler()
}
