package intent

// Review is immutable display content supplied by a trusted application. Intent
// authenticates the human's approval; the application owns what approval permits.
// Put untrusted caller claims in Details and label their provenance in Summary.
type Review struct {
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Details string `json:"details"`
}
