package indicators

import "encoding/base64"

func b64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
