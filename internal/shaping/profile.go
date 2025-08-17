package shaping

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
)

// Profile defines the statistical model for a traffic pattern.
type Profile struct {
	Name                   string                 `json:"name"`
	PacketSizeDistribution SizeDistribution       `json:"packet_size_distribution"`
	IntervalDistributionMs IntervalDistribution `json:"interval_distribution_ms"`
}

// SizeDistribution defines how to generate packet sizes.
type SizeDistribution struct {
	Type    string `json:"type"`
	Buckets []struct {
		Size        int     `json:"size"`
		Probability float64 `json:"probability"`
	} `json:"buckets"`
}

// IntervalDistribution defines how to generate send intervals.
type IntervalDistribution struct {
	Type   string  `json:"type"`
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"stddev"`
}

// LoadProfile loads a traffic shaping profile from a JSON file.
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile file: %w", err)
	}

	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse profile json: %w", err)
	}

	// Validate profile data
	if p.PacketSizeDistribution.Type == "histogram" {
		var totalProb float64
		for _, bucket := range p.PacketSizeDistribution.Buckets {
			totalProb += bucket.Probability
		}
		if totalProb < 0.99 || totalProb > 1.01 { // Allow for float inaccuracies
			return nil, fmt.Errorf("probabilities in packet size distribution do not sum to 1")
		}
	}

	return &p, nil
}

// GetRandomSize generates a random packet size based on the distribution.
func (p *Profile) GetRandomSize() int {
	if p.PacketSizeDistribution.Type == "histogram" {
		r := rand.Float64()
		var cumulativeProb float64
		for _, bucket := range p.PacketSizeDistribution.Buckets {
			cumulativeProb += bucket.Probability
			if r < cumulativeProb {
				return bucket.Size
			}
		}
	}
	// Default fallback
	return 100
}

// GetRandomIntervalMs generates a random interval in milliseconds based on the distribution.
func (p *Profile) GetRandomIntervalMs() float64 {
	if p.IntervalDistributionMs.Type == "gaussian" {
		interval := rand.NormFloat64()*p.IntervalDistributionMs.StdDev + p.IntervalDistributionMs.Mean
		if interval < 0 {
			interval = 0
		}
		return interval
	}
	// Default fallback
	return p.IntervalDistributionMs.Mean
}
