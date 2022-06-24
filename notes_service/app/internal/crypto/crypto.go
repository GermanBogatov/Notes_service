package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

const (
	PublicE = 65537
	PublicN = "25238893363167817673397141041041044262618682687894783128250341260001487325651231776680153884146474543334906289178231293636463066116507379186161981408104393842247956145828969301669552769995479918735570331525045719007420538082322399194515093366297481967476810987987717680200768500051735489114899252418523345894116733947565980815362070353373955492742938600874019096206362924247406518652582581291532847476744570421800465935289656586738836336067197897925065521927016177173243847589764739305797832593556790596278744309265852852980493462398471916536086938568773642213816420966053146341267697977635314508062648959406604070571"
)

func EncryptAES256(stringToEncrypt string, keyString string) (encryptedString string) {

	key, err := hex.DecodeString(keyString)
	if err != nil {
		panic(err.Error())
	}
	plaintext := []byte(stringToEncrypt)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

func DecryptAES256(encryptedString string, keyString string) (decryptedString string) {

	key, err := hex.DecodeString(keyString)
	if err != nil {
		panic(err.Error())
	}
	enc, err := hex.DecodeString(encryptedString)
	if err != nil {
		panic(err.Error())
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return fmt.Sprintf("%s", plaintext)
}

func GenerateKeyUIID() (key string) {
	bytesuuid := make([]byte, 16)
	if _, err := rand.Read(bytesuuid); err != nil {
		panic(err.Error())
	}
	key = hex.EncodeToString(bytesuuid)
	return key
}

func VerifySIGN(msg, sign string) bool {
	message := []byte(msg)
	hashed := sha256.Sum256(message)
	signature, _ := hex.DecodeString(sign)
	PublicKey := new(rsa.PublicKey)
	PublicKey.N = big.NewInt(0)
	PublicKey.N.UnmarshalText([]byte(PublicN))
	PublicKey.E = PublicE
	err := rsa.VerifyPKCS1v15(PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		//	fmt.Fprintf(os.Stderr, "Error from verification: %s\n", err)
		return false
	}
	return true
	/*
		var err error
		PublicKeytest := new(rsa.PublicKey)
		PublicKeytest.N = big.NewInt(0)
		PublicKeytest.N.UnmarshalText([]byte("20933338182917853299122740512429178838987384525666752589329040489081021223826014920926681945599325507003956545280203562520002329984109183377892904917087577272006780661052488265382372375191358968529093604220421656612430217957346004330466411353051833072925939287278132420557875425378462150289416885932376995270087786398640172993268730168208772137656957245907481387522179102082636328353544363859173085517515635700020012457516310578481156294546051553343202956871762275717500682915569514719530978938331512166133218272790898174535916689481820662944792812230738153581732871693316111617680673548228039310552394322795228581693"))
		PublicKeytest.E = 65537
		fmt.Println("message: ", msg)
		fmt.Println("signature: ", signature)
		fmt.Println("public key: ", PublicKeytest)
		signaturetest, _ := hex.DecodeString(signature)
		msgverify := []byte(msg)
		msgHashverify := sha256.New()
		_, err = msgHashverify.Write(msgverify)
		if err != nil {
			panic(err)
		}
		msgHashSumtest := msgHashverify.Sum(nil)
		err = rsa.VerifyPKCS1v15(PublicKeytest, crypto.SHA256, msgHashSumtest, signaturetest)
		if err != nil {
			return false
		}
		return true*/
}
