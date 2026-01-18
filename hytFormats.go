
package main
import (
	"time"
)
type launcherData struct {
	EulaAcceptedAt time.Time  `json:"eula_accepted_at"`
	Owner          string     `json:"owner"`
	Patchlines     patchlines `json:"patchlines"`
	Profiles       []accountInfo `json:"profiles"`
}
type gameVersion struct {
	BuildVersion string `json:"buildVersion"`
	Newest       int    `json:"newest"`
}
type patchlines struct {
	PreRelease gameVersion `json:"pre-release"`
	Release    gameVersion    `json:"release"`
}


type accountInfo struct {
	CreatedAt        time.Time `json:"createdAt"`
	Entitlements     []string  `json:"entitlements"`
	NextNameChangeAt time.Time `json:"nextNameChangeAt"`
	Skin             string    `json:"skin"`
	Username         string    `json:"username"`
	UUID             string    `json:"uuid"`
}
// there is more to it than this, this is just all we have to care about ...
type cosmeticDefinition struct {
	Id string `json:"Id"`
}

type cosmeticsInventory struct {
	BodyCharacteristic []string `json:"bodyCharacteristic"`
	Cape               []string `json:"cape"`
	EarAccessory       []string `json:"earAccessory"`
	Ears               []string `json:"ears"`
	Eyebrows           []string `json:"eyebrows"`
	Eyes               []string `json:"eyes"`
	Face               []string `json:"face"`
	FaceAccessory      []string `json:"faceAccessory"`
	FacialHair         []string `json:"facialHair"`
	Gloves             []string `json:"gloves"`
	Haircut            []string `json:"haircut"`
	HeadAccessory      []string `json:"headAccessory"`
	Mouth              []string `json:"mouth"`
	Overpants          []string `json:"overpants"`
	Overtop            []string `json:"overtop"`
	Pants              []string `json:"pants"`
	Shoes              []string `json:"shoes"`
	SkinFeature        []string `json:"skinFeature"`
	Undertop           []string `json:"undertop"`
	Underwear          []string `json:"underwear"`
}

type versionStep struct {
	From int    `json:"from"`
	Pwr  string `json:"pwr"`
	Sig  string `json:"sig"`
	To   int    `json:"to"`
}
type versionManifest struct {
	Steps []versionStep `json:"steps"`
}


type hashedDownload struct {
	URL    string `json:"url"`
	Sha256 string `json:"sha256"`
}
type osVarient struct {
	Arm64 hashedDownload `json:"arm64"`
	Amd64 hashedDownload `json:"amd64"`
}
type downloadUrls struct {
	Linux   osVarient `json:"linux"`
	Darwin  osVarient `json:"darwin"`
	Windows osVarient `json:"windows"`
}

type versionFeed struct {
	Version string   `json:"version"`
	DownloadUrls downloadUrls `json:"download_url"`
}

type sessionNew struct {
	ExpiresAt     time.Time `json:"expiresAt"`
	IdentityToken string    `json:"identityToken"`
	SessionToken  string    `json:"sessionToken"`
}
