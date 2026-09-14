package wire

import "testing"

type testByteView []byte

func (v testByteView) Len() int      { return len(v) }
func (v testByteView) At(i int) byte { return v[i] }
func TestBorrowedBytes(t *testing.T) {
	source := testByteView{1, 2, 3}
	value := BorrowedBytesValue(source)
	record, err := NewWireRecord(FamilyIPv4, []Value{value})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := record.Values()
	source[0] = 9
	if snapshot[0].Octets() != string([]byte{1, 2, 3}) {
		t.Fatal("owned snapshot retained source")
	}
	borrowed, _ := record.ValueAt(0)
	if borrowed.ByteLen() != 3 || borrowed.ByteAt(0) != 9 {
		t.Fatal("view unexpectedly copied")
	}
	if allocations := testing.AllocsPerRun(1000, func() { v, _ := record.ValueAt(0); _ = v.ByteLen(); _ = v.ByteAt(0) }); allocations != 0 {
		t.Fatalf("view access allocated: %v", allocations)
	}
}
