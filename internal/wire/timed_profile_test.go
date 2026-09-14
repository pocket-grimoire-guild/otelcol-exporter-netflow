package wire

import "testing"

func TestBuiltinV9TimedProfile(t *testing.T) {
	core := BuiltinV9()
	timed := BuiltinV9Timed()
	if timed.Protocol() != ProtocolV9 || timed.ShapeCount() != 2 {
		t.Fatalf("timed catalog protocol=%v shapes=%d", timed.Protocol(), timed.ShapeCount())
	}
	wantIDs := []uint16{1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 34, 52, 60, 22, 21}
	wantWidths := []uint16{4, 4, 1, 1, 1, 2, 4, 1, 2, 2, 4, 1, 2, 4, 4, 4, 1, 1, 4, 4}
	for i, family := range []Family{FamilyIPv4, FamilyIPv6} {
		shape, ok := timed.ShapeAt(i)
		legacy, legacyOK := core.ShapeAt(i)
		if !ok || !legacyOK || shape.Family() != family || shape.ID() != uint16(256+i) || shape.FieldCount() != 20 || shape.RecordLength() != []uint64{51, 75}[i] || shape.TemplateBytes() != 88 {
			t.Fatalf("shape %d family=%v id=%d fields=%d record=%d template=%d", i, shape.Family(), shape.ID(), shape.FieldCount(), shape.RecordLength(), shape.TemplateBytes())
		}
		if legacy.FieldCount() != 18 || legacy.RecordLength() != []uint64{43, 67}[i] || legacy.TemplateBytes() != 80 {
			t.Fatalf("core shape %d changed: fields=%d record=%d template=%d", i, legacy.FieldCount(), legacy.RecordLength(), legacy.TemplateBytes())
		}
		for field := range legacy.Fields() {
			got, _ := shape.DescriptorAt(field)
			want, _ := legacy.DescriptorAt(field)
			if got != want {
				t.Fatalf("timed shape %d changed core field %d: got=%+v want=%+v", i, field, got, want)
			}
		}
		for field, descriptor := range shape.Fields() {
			wantID, wantWidth := wantIDs[field], wantWidths[field]
			if i == 1 {
				if field == 6 {
					wantID, wantWidth = 27, 16
				}
				if field == 7 {
					wantID = 29
				}
				if field == 10 {
					wantID, wantWidth = 28, 16
				}
				if field == 11 {
					wantID = 30
				}
			}
			if descriptor.ID != wantID || descriptor.Length != wantWidth {
				t.Fatalf("timed shape %d field %d=%d/%d, want %d/%d", i, field, descriptor.ID, descriptor.Length, wantID, wantWidth)
			}
		}
	}
	if err := timed.Validate(); err != nil {
		t.Fatalf("timed catalog validation: %v", err)
	}
}
