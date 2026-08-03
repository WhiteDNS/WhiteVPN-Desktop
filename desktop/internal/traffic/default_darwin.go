//go:build darwin

package traffic

func DefaultSampler() Sampler {
	return NettopSampler{}
}
