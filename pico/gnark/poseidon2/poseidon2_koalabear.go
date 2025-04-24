package poseidon2

import (
	"github.com/brevis-network/pico/gnark/koalabear"
	"github.com/consensys/gnark/frontend"
	"math/big"
)

const KOALABEAR_WIDTH = 16
const koalabearNumExternalRounds = 8
const koalabearNumInternalRounds = 20

type Poseidon2KoalaBearChip struct {
	State       [16]koalabear.Variable
	bufferCount int

	api      frontend.API
	fieldApi *koalabear.Chip
}

func NewKoalaBearChip(api frontend.API) *Poseidon2KoalaBearChip {
	return &Poseidon2KoalaBearChip{
		State: [16]koalabear.Variable{
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
		},
		api:      api,
		fieldApi: koalabear.NewChip(api),
	}
}

func (p *Poseidon2KoalaBearChip) Update(input koalabear.Variable) {
	p.State[p.bufferCount] = p.fieldApi.AddF(p.State[p.bufferCount], input)
	p.bufferCount = p.bufferCount + 1

	if p.bufferCount == 15 {
		p.PermuteMut(&p.State)
		p.bufferCount = 0
	}
}

func (p *Poseidon2KoalaBearChip) Finalize() [16]koalabear.Variable {
	if p.bufferCount > 0 {
		p.State[p.bufferCount] = p.fieldApi.AddF(p.State[p.bufferCount], koalabear.One())
	} else {
		p.State[0] = p.fieldApi.AddF(p.State[0], koalabear.One())
	}
	p.PermuteMut(&p.State)

	res := [16]koalabear.Variable{}
	for i := 0; i < 16; i++ {
		res[i] = p.State[i]
	}
	return res
}

func (p *Poseidon2KoalaBearChip) PermuteMut(state *[KOALABEAR_WIDTH]koalabear.Variable) {
	// The initial linear layer.
	p.externalLinearLayer(state)

	// The first half of the external rounds.
	rounds := koalabearNumExternalRounds + koalabearNumInternalRounds
	roundsFBeginning := koalabearNumExternalRounds / 2
	for r := 0; r < roundsFBeginning; r++ {
		p.addRc(state, rc16_koalabear[r])
		p.sbox(state)
		p.externalLinearLayer(state)
	}

	// The internal rounds.
	p_end := roundsFBeginning + koalabearNumInternalRounds
	for r := roundsFBeginning; r < p_end; r++ {
		state[0] = p.fieldApi.AddF(state[0], rc16_koalabear[r][0])
		state[0] = p.sboxP(state[0])
		p.diffusionPermuteMut(state)
	}

	// The second half of the external rounds.
	for r := p_end; r < rounds; r++ {
		p.addRc(state, rc16_koalabear[r])
		p.sbox(state)
		p.externalLinearLayer(state)
	}
}

func (p *Poseidon2KoalaBearChip) addRc(state *[KOALABEAR_WIDTH]koalabear.Variable, rc [KOALABEAR_WIDTH]koalabear.Variable) {
	for i := 0; i < KOALABEAR_WIDTH; i++ {
		state[i] = p.fieldApi.AddF(state[i], rc[i])
	}
}

func (p *Poseidon2KoalaBearChip) sboxP(input koalabear.Variable) koalabear.Variable {
	zero := koalabear.NewFConst("0")
	inputCpy := p.fieldApi.AddF(input, zero)
	inputCpy = p.fieldApi.ReduceSlow(inputCpy)
	inputValue := inputCpy.Value
	i2 := p.api.Mul(inputValue, inputValue)
	i3 := p.api.Mul(i2, inputValue)
	i3bb := p.fieldApi.ReduceSlow(koalabear.Variable{
		Value:      i3,
		UpperBound: new(big.Int).Exp(new(big.Int).SetUint64(2130706433), new(big.Int).SetUint64(3), new(big.Int).SetUint64(0)),
	})
	return i3bb
}

func (p *Poseidon2KoalaBearChip) sbox(state *[KOALABEAR_WIDTH]koalabear.Variable) {
	for i := 0; i < KOALABEAR_WIDTH; i++ {
		state[i] = p.sboxP(state[i])
	}
}

func (p *Poseidon2KoalaBearChip) mdsLightPermutation4x4(state []koalabear.Variable) {
	t01 := p.fieldApi.AddF(state[0], state[1])
	t23 := p.fieldApi.AddF(state[2], state[3])
	t0123 := p.fieldApi.AddF(t01, t23)
	t01123 := p.fieldApi.AddF(t0123, state[1])
	t01233 := p.fieldApi.AddF(t0123, state[3])
	state[3] = p.fieldApi.AddF(t01233, p.fieldApi.MulFConst(state[0], 2))
	state[1] = p.fieldApi.AddF(t01123, p.fieldApi.MulFConst(state[2], 2))
	state[0] = p.fieldApi.AddF(t01123, t01)
	state[2] = p.fieldApi.AddF(t01233, t23)
}

func (p *Poseidon2KoalaBearChip) externalLinearLayer(state *[KOALABEAR_WIDTH]koalabear.Variable) {
	for i := 0; i < KOALABEAR_WIDTH; i += 4 {
		p.mdsLightPermutation4x4(state[i : i+4])
	}

	sums := [4]koalabear.Variable{
		state[0],
		state[1],
		state[2],
		state[3],
	}
	for i := 4; i < KOALABEAR_WIDTH; i += 4 {
		sums[0] = p.fieldApi.AddF(sums[0], state[i])
		sums[1] = p.fieldApi.AddF(sums[1], state[i+1])
		sums[2] = p.fieldApi.AddF(sums[2], state[i+2])
		sums[3] = p.fieldApi.AddF(sums[3], state[i+3])
	}

	for i := 0; i < KOALABEAR_WIDTH; i++ {
		state[i] = p.fieldApi.AddF(state[i], sums[i%4])
	}
}

func (p *Poseidon2KoalaBearChip) diffusionPermuteMut(state *[KOALABEAR_WIDTH]koalabear.Variable) {
	matInternalDiagM1 := [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("2130706431"),
		koalabear.NewFConst("1"),
		koalabear.NewFConst("2"),
		koalabear.NewFConst("1065353217"),
		koalabear.NewFConst("3"),
		koalabear.NewFConst("4"),
		koalabear.NewFConst("1065353216"),
		koalabear.NewFConst("2130706430"),
		koalabear.NewFConst("2130706429"),
		koalabear.NewFConst("2122383361"),
		koalabear.NewFConst("1864368129"),
		koalabear.NewFConst("2130706306"),
		koalabear.NewFConst("8323072"),
		koalabear.NewFConst("266338304"),
		koalabear.NewFConst("133169152"),
		koalabear.NewFConst("127"),
	}
	p.matmulInternal(state, &matInternalDiagM1)
}

func (p *Poseidon2KoalaBearChip) matmulInternal(
	state *[KOALABEAR_WIDTH]koalabear.Variable,
	matInternalDiagM1 *[KOALABEAR_WIDTH]koalabear.Variable,
) {
	sum := koalabear.NewFConst("0")
	for i := 0; i < KOALABEAR_WIDTH; i++ {
		sum = p.fieldApi.AddF(sum, state[i])
	}

	for i := 0; i < KOALABEAR_WIDTH; i++ {
		state[i] = p.fieldApi.MulF(state[i], matInternalDiagM1[i])
		state[i] = p.fieldApi.AddF(state[i], sum)
	}
}
