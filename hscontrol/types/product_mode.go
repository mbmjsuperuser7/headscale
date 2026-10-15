package types

type ProductMode string

const (
	ProductHorizon ProductMode = "horizon"
	ProductGlue    ProductMode = "glue"
)

func (m ProductMode) IsGlue() bool    { return m == ProductGlue }
func (m ProductMode) IsHorizon() bool { return m == ProductHorizon || m == "" }
