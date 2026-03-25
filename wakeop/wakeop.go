// Package wakeop constructs the FUTEX_OP value for [futex.WakeOp]().
package wakeop

// Op can be passed to [futex.WakeOp]().
type Op uint32

type PartialOp struct {
	op uint32
}

func newPartialOp(op, oparg uint32) PartialOp {
	if oparg&^0xff != 0 {
		panic("FUTEX_OP doesn't allow more than 12 bits of oparg")
	}
	return PartialOp{(op << 28) | (oparg << 12)}
}

func Set(oparg uint32) PartialOp  { return newPartialOp(0, oparg) }
func Add(oparg uint32) PartialOp  { return newPartialOp(1, oparg) }
func Or(oparg uint32) PartialOp   { return newPartialOp(2, oparg) }
func AndN(oparg uint32) PartialOp { return newPartialOp(3, oparg) }
func Xor(oparg uint32) PartialOp  { return newPartialOp(4, oparg) }

func (p PartialOp) finishOp(cmp, cmparg uint32) Op {
	if cmparg&^0xff != 0 {
		panic("FUTEX_OP doesn't allow more than 12 bits of cmparg")
	}
	return Op(p.op | (cmp << 24) | cmparg)
}

func (p PartialOp) CmpEq(cmparg uint32) Op { return p.finishOp(0, cmparg) }
func (p PartialOp) CmpNe(cmparg uint32) Op { return p.finishOp(1, cmparg) }
func (p PartialOp) CmpLt(cmparg uint32) Op { return p.finishOp(2, cmparg) }
func (p PartialOp) CmpLe(cmparg uint32) Op { return p.finishOp(3, cmparg) }
func (p PartialOp) CmpGt(cmparg uint32) Op { return p.finishOp(4, cmparg) }
func (p PartialOp) Cmpge(cmparg uint32) Op { return p.finishOp(5, cmparg) }
