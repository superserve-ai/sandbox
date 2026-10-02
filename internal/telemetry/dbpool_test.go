package telemetry

import "testing"

func TestSaturationDetector(t *testing.T) {
	type sample struct {
		zeroIdle bool
		waited   bool
	}
	// shorthand: h = zero-idle hold sample without wait evidence,
	// w = zero-idle sample with wait/cancel evidence, i = idle present.
	h := sample{zeroIdle: true}
	w := sample{zeroIdle: true, waited: true}
	i := sample{}

	tests := []struct {
		name    string
		samples []sample
		want    []bool
	}{
		{
			name:    "fires on the threshold sample when every sample carries evidence",
			samples: []sample{w, w, w, w},
			want:    []bool{false, false, false, true},
		},
		{
			name:    "quiet zero-idle samples hold the streak; one evidence sample arms it",
			samples: []sample{h, h, h, w},
			want:    []bool{false, false, false, true},
		},
		{
			name:    "evidence early in the episode still counts at threshold",
			samples: []sample{w, h, h, h},
			want:    []bool{false, false, false, true},
		},
		{
			name:    "full utilization without any wait evidence never fires",
			samples: []sample{h, h, h, h, h, h},
			want:    []bool{false, false, false, false, false, false},
		},
		{
			name:    "does not refire while the episode continues",
			samples: []sample{w, w, w, w, w, w},
			want:    []bool{false, false, false, true, false, false},
		},
		{
			name:    "idle sample resets streak and evidence",
			samples: []sample{w, w, i, w, w, w, w},
			want:    []bool{false, false, false, false, false, false, true},
		},
		{
			name:    "re-arms after the episode ends and fires on the next one",
			samples: []sample{w, w, w, w, i, w, w, w, w},
			want:    []bool{false, false, false, true, false, false, false, false, true},
		},
		{
			name:    "wait evidence with idle connections present does not build a streak",
			samples: []sample{i, i, i, i},
			want:    []bool{false, false, false, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var det saturationDetector
			for n, smp := range tt.samples {
				if got := det.observe(smp.zeroIdle, smp.waited); got != tt.want[n] {
					t.Errorf("sample %d (zeroIdle=%v waited=%v): observe() = %v, want %v", n, smp.zeroIdle, smp.waited, got, tt.want[n])
				}
			}
		})
	}
}
