package crypto

import (
	// "fmt"
	// "math"
	"math/big"
	// "errors"
	// "strconv"
	// "bytes"
	// "unsafe"
	"crypto/sha256"
	"crypto/sha512"
	"ed25519"
	"reflect"
	// "github.com/ethereum/go-ethereum/crypto/ed25519"
)

// -------------------------------

// Sent out at end of commitment phase ((vi,ci,πi))
type CommitmentMessage struct {
	encrypted_shares []ed25519.Point
	proof            ShareCorrectnessProof
}

// Sent out at end of aggragation phase (root,ˆv,ˆc,I, ̄cj, ̄πj, ̄vj,ht,X)
type AggregationMessage struct {
	root                []byte            // merkle root
	aggregated_commit   []ed25519.Point   // ˆv
	aggregated_encshare []ed25519.Point   // ˆc
	I_list              []int             // I
	proofs              CommitmentMessage // (cj, ̄πj, ̄vj)
	height              int               //ht
	X                   Ht_proof          // ht proof
}

//Sent out at end of prepare phase
type PrepareMessage struct {
	root []byte
}

// sent out during reconstruction phase( ̃sj, ̃πj)
type ReconstructionMessage struct {
	secret ed25519.Point         // sj
	proof  ShareCorrectnessProof //πj
}

// -----------------------------------

// var temp = make([] byte,32)
var G = Point_G()
var H = ed25519.B

type ShareCorrectnessProof struct {
	commitments []ed25519.Point
	challenge   ed25519.Scalar
	responses   []ed25519.Scalar
}

type ShareDecryptionProof struct {
	challenge ed25519.Scalar
	response  []ed25519.Scalar
}

type Ht_proof struct {
}

type Polynomial struct {
	coeffs []ed25519.Scalar
}

func Point_G() ed25519.Point {
	has := sha256.New()
	has.Write(ed25519.B.Val)
	bs := has.Sum(nil)
	Pt, _ := ed25519.Point_from_uniform(bs)
	return Pt
}

// Initializes polynomial with given coefficients
func (p Polynomial) Init(s []ed25519.Scalar) {
	copy(p.coeffs, s)
}

// evaluates polynomial at arg and returns evaluation (TODO:look for optimizations)
func (p Polynomial) Eval(arg int) ed25519.Scalar {
	x := ed25519.New_scalar(*big.NewInt(int64(arg)))
	result := p.coeffs[0].Add(p.coeffs[1].Mul(x))
	x_pow := x.Copy()
	for i := 2; i < len(p.coeffs); i++ {
		x_pow = x_pow.Mul(x)
		result = result.Add(p.coeffs[i].Mul(x_pow))
	}
	return result
}

// Return a polynomial with random coefficients from Zq.
//           p(x) = c_0 + c_1*x + ... c_{degree} * x^{degree}

func Random_with_secret(degree int, secret ed25519.Scalar) Polynomial {
	var coeffs []ed25519.Scalar
	coeffs = append(coeffs, secret)
	for i := 1; i <= degree; i++ {
		coeffs = append(coeffs, ed25519.Random())
	}
	return Polynomial{coeffs}
}

// similar to above function . But randomly chooses secret Scalar parameter
func Random(degree int) Polynomial {
	var coeffs []ed25519.Scalar
	for i := 0; i <= degree; i++ {
		coeffs = append(coeffs, ed25519.Random())
	}
	return Polynomial{coeffs}
}

// --------------------------

// generates a fresh ed25519 keypair (sk, pk = h^sk) for a participant in the PVSS protocol
func Keygen() (ed25519.Scalar, ed25519.Point) {
	secret_key := ed25519.Random()
	public_key := H.Mul(secret_key)
	return secret_key, public_key
}

// Use this function to send message to leader in Commitment phase
func Share_random_secret(receiver_public_keys []ed25519.Point, recovery_threshold int, secret_scalar ed25519.Scalar) CommitmentMessage {
	//  generate a fresh random base secret s (or uses the provided one)
	// computes share (s_1, ..., s_n) for S = h^s
	// encrypts them with the public keys to obtain ŝ_1, ..., ŝ_n
	// compute the verification information
	// returns

	//  - the encrypted shares ŝ_1, ..., ŝ_n
	//  - the share verification information, i.e. PROOF_D, which consists of
	// 	- the commitments v_1, ..., v_n   (v_i = g^{s_i})
	// 	- the (common) challenge e
	// 	- the responses z_1, ..., z_n

	num_receivers := len(receiver_public_keys)
	secret := secret_scalar
	poly := Random_with_secret(recovery_threshold-1, secret)
	var shares []ed25519.Scalar
	for i := 1; i <= num_receivers; i++ {
		shares = append(shares, poly.Eval(i))
	}
	var encrypted_shares []ed25519.Point
	for j := 0; j < num_receivers; j++ {
		encrypted_shares = append(encrypted_shares, receiver_public_keys[j].Mul(shares[j]))
	}
	proof := Prove_share_correctness(shares, encrypted_shares, receiver_public_keys)

	return CommitmentMessage{encrypted_shares, proof}
}

// // Only used for benchmarking
// func GenerateShares(recovery_threshold int) {

// }

// encryptedshare * secret_key.inverse()
func Decrypt_share(share ed25519.Point, secret_key ed25519.Scalar) ed25519.Point {
	return share.Mul(secret_key.Inverse())
}

// Performs a the DLEQ NIZK protocol for the given values g, x, h, y and the exponent α.
//         I.e. the prover shows that he knows α such that x = g^α and y = h^α holds.
//         Returns challenge e and z to verifier
// Batch proof generation (g=[G]*n,h=[H]*n,x=[g^a,g^b..],y=[h^a,h^b..],α=[a,b,...])
// e= joint challenge computed as in section 2.6 of Scrape
// e = H(x[1], y[1], . . . , x[n], y[n], a1[1],a2[1], . . . , a1[n],a2[n])
func DLEQ_prove(g []ed25519.Point, h []ed25519.Point, x []ed25519.Point, y []ed25519.Point, α []ed25519.Scalar) (ed25519.Scalar, []ed25519.Scalar) {
	n := len(g)
	if n != len(x) || n != len(h) || n != len(y) || n != len(α) {
		panic("Lenghts are not equal!")
	}
	var w []ed25519.Scalar // w random element  from Zq
	for i := 0; i < n; i++ {
		w = append(w, ed25519.Random())
	}
	var a1 []ed25519.Point // a1 = g^w
	for i := 0; i < n; i++ {
		a1 = append(a1, g[i].Mul(w[i]))
	}
	var a2 []ed25519.Point // a2 = h^w
	for i := 0; i < n; i++ {
		a2 = append(a2, h[i].Mul(w[i]))
	}
	e := DLEQ_derive_challenge(x, y, a1, a2) // the challenge e

	var z []ed25519.Scalar
	for i := 0; i < n; i++ {
		z = append(z, w[i].Sub(α[i].Mul(e))) // z[i] = w[i]-α[i]*(e)
	}

	return e, z

}

// Performs a the verification procedure of DLEQ NIZK protocol for the given values g, x, h, y (g=[G]*n,h=[H]*n,x=[g^a,g^b..],y=[h^a,h^b..])
//e = H(x[1], y[1], . . . , x[n], y[n], a1[1],a2[1], . . . , a1[n],a2[n])

func DLEQ_verify(g []ed25519.Point, h []ed25519.Point, x []ed25519.Point, y []ed25519.Point, e ed25519.Scalar, z []ed25519.Scalar) bool {
	n := len(g)
	if n != len(x) || n != len(h) || n != len(y) || n != len(z) {
		panic("Lenghts are not equal(DLEQ Verify)!")
	}
	var a1 []ed25519.Point
	for i := 0; i < n; i++ {
		a1 = append(a1, g[i].Mul(z[i]).Add(x[i].Mul(e))) // a1[i]= g[i]^(z[i])+x[i]^(e)
	}
	var a2 []ed25519.Point
	for i := 0; i < n; i++ {
		a2 = append(a2, h[i].Mul(z[i]).Add(y[i].Mul(e))) // a2[i]= h[i]^(z[i])+y[i]^(e)
	}
	e_computed := DLEQ_derive_challenge(x, y, a1, a2)
	return reflect.DeepEqual(e, e_computed)
}

//Compute (common) challenge e = H(x, y, a1,a2).
// a1[i]= g[i]^(z[i])+x[i]^(e),a2[i]= h[i]^(z[i])+y[i]^(e)  ,x=[g^a,g^b..],y=[h^a,h^b..]
// e = H(x[1], y[1], . . . , x[n], y[n], a1[1],a2[1], . . . , a1[n],a2[n])
func DLEQ_derive_challenge(x []ed25519.Point, y []ed25519.Point, a1 []ed25519.Point, a2 []ed25519.Point) ed25519.Scalar {
	n := len(x)
	var bytestring []byte
	for i := 0; i < n; i++ {
		bytestring = append(bytestring, x[i].Val...)
		bytestring = append(bytestring, y[i].Val...)
		bytestring = append(bytestring, a1[i].Val...)
		bytestring = append(bytestring, a2[i].Val...)
	}
	has := sha512.New()
	has.Write(bytestring)
	bs := has.Sum(nil)
	return ed25519.Scalar_reduce(bs)
}

// Returns commitments to the shares and a NIZK proof (DLEQ) proofing that
// the encrypted_shares are correctly derived.

// # notation used in Scrape paper and analogs here
// # x... commitments
// # y... encrypted shares
// # g... G
// # h... public_keys
// # α... shares
// # e... challenge
// # z... responses
func Cdword() []ed25519.Scalar {
	var cword [10]*big.Int
	cword[0], _ = new(big.Int).SetString("7203752667060718521734215896703962279101657476402191189251245996724719624102", 10)
	cword[1], _ = new(big.Int).SetString("6584376362115823197202689089693273679479879129476924448596111322855581237506", 10)
	cword[2], _ = new(big.Int).SetString("2849277567941235307516871542473254642270224799518486212917363740099653844831", 10)
	cword[3], _ = new(big.Int).SetString("4853174043442147999248547217404786911129256704648520386357112663949381556647", 10)
	cword[4], _ = new(big.Int).SetString("6958052009448536247520974790618860640556537967216134899705152344809220810112", 10)
	cword[5], _ = new(big.Int).SetString("1775448883856868114031645279414320427271576865803559115050333772248955483980", 10)
	cword[6], _ = new(big.Int).SetString("4691153190195877468938773701976307356173981692739176183347771799031041957128", 10)
	cword[7], _ = new(big.Int).SetString("2404771991859104582600832228630557134285179341682391480427294358488543256597", 10)
	cword[8], _ = new(big.Int).SetString("4236347200941808160053689493810840548045358291324178821843102380261404889925", 10)
	cword[9], _ = new(big.Int).SetString("1865679547131453684990880137531801826829045887467882898516217251244222845106", 10)
	var scdword []ed25519.Scalar
	for j := 0; j < 10; j++ {
		scdword = append(scdword, ed25519.New_scalar(*cword[j]))
	}
	return scdword
}

func Prove_share_correctness(shares []ed25519.Scalar, encrypted_shares []ed25519.Point, public_keys []ed25519.Point) ShareCorrectnessProof {
	// return ShareCorrectnessProof{[]ed25519.Point{ed25519.Raw_point()},ed25519.Raw_scalar(),[]ed25519.Scalar{ed25519.Raw_scalar()}}
	n := len(shares)
	var commitments []ed25519.Point
	for i := 0; i < len(shares); i++ {
		commitments = append(commitments, G.Mul(shares[i]))
	}
	if n != len(commitments) || n != len(public_keys) || n != len(encrypted_shares) || n != len(shares) {
		panic("Lengths not equal!")
	}
	var G_bytestring []ed25519.Point
	for j := 0; j < n; j++ {
		G_bytestring = append(G_bytestring, G)
	}
	// DLEQ_prove([g,g,g, ..],[g^s[0],g^s[1]....],[h^sk[0],h^sk[1]],[pk[0]^s[0],pk[1]^sk[1]],[s[0],s[1]....])
	challenge, responses := DLEQ_prove(G_bytestring, public_keys, commitments, encrypted_shares, shares)
	return ShareCorrectnessProof{commitments, challenge, responses}

}

// """ Verify that the given encrypted shares are computed accoring to the protocol.
// Returns True if the encrypted shares are valid.
// If this functions returns True, a collaboration of t nodes is able to recover the secret S.
// """

func Verify_shares(encrypted_shares []ed25519.Point, proof ShareCorrectnessProof, public_keys []ed25519.Point, recovery_threshold int) bool {
	num_nodes := len(public_keys)
	commitments, challenge, responses := proof.commitments, proof.challenge, proof.responses

	var G_bytestring []ed25519.Point
	for j := 0; j < num_nodes; j++ {
		G_bytestring = append(G_bytestring, G)
	}
	// 1. verify the DLEQ NIZK proof
	if !DLEQ_verify(G_bytestring, public_keys, commitments, encrypted_shares, challenge, responses) {
		return false
	}

	// 2. verify the validity of the shares by sampling and testing with a random codeword

	codeword := Random_codeword(num_nodes, recovery_threshold)
	// codeword := Cdword()
	product := commitments[0].Mul(codeword[0])
	// fmt.Println(len(codeword))
	// fmt.Println(len(commitments))
	for i := 1; i < num_nodes; i++ {
		product = product.Add(commitments[i].Mul(codeword[i]))
	}
	// fmt.Println(product)
	// fmt.Println(ed25519.ONE)
	return product.Equal(ed25519.ONE)

}

func Verify_shares_no_codeword(encrypted_shares []ed25519.Point, proof ShareCorrectnessProof, public_keys []ed25519.Point, recovery_threshold int) bool {
	num_nodes := len(public_keys)
	commitments, challenge, responses := proof.commitments, proof.challenge, proof.responses

	var G_bytestring []ed25519.Point
	for j := 0; j < num_nodes; j++ {
		G_bytestring = append(G_bytestring, G)
	}
	// 1. verify the DLEQ NIZK proof
	if !DLEQ_verify(G_bytestring, public_keys, commitments, encrypted_shares, challenge, responses) {
		return false
	}

	// 2. verify the validity of the shares by sampling and testing with a random codeword

	// codeword := Random_codeword(num_nodes, recovery_threshold)
	// // codeword := Cdword()
	// product := commitments[0].Mul(codeword[0])
	// // fmt.Println(len(codeword))
	// // fmt.Println(len(commitments))
	// for i := 1; i < num_nodes; i++ {
	// 	product = product.Add(commitments[i].Mul(codeword[i]))
	// }
	// fmt.Println(product)
	// fmt.Println(ed25519.ONE)
	return true

}

// """ Checks if a revealed secret indeed corresponding to a provided commitment.
//         Returns True if the secret is valid.
//         Returns False is the secret is invalid.
//         Also returns False if the secret is valid but the commitment
//         (i.e. the coefficients of the underlying polynomial) where not derive according to the protocol.
//     """

// # 1. Obtain v_0 via Langrange interpolation from v_1, ..., v_t, or from any other t-sized subset of {v_1, ..., v_n}.
//     #    This is possible as the commitments v_1, ... v_n are all public information after the secret has been shared.
//     # 2. Use the fact v_0 = g^p(0) = g^s to verify that the given secret s is valid.
func Verify_secret(secret ed25519.Scalar, commitments []ed25519.Point, recovery_threshold int) bool { // TODO: change this
	v0 := Recover(commitments, recovery_threshold)
	return v0.Equal(G.Mul(secret))
}

// """ Proves that decrypted_share is a valid decryption for the given public key.
// i.e. implements DLEQ(h, pk_i, s~_i, ŝ_i)
// """
func Prove_share_decryption(decrypted_share ed25519.Point, encrypted_share ed25519.Point, secret_key ed25519.Scalar, public_key ed25519.Point) ShareDecryptionProof {
	challenge, response := DLEQ_prove([]ed25519.Point{H}, []ed25519.Point{decrypted_share}, []ed25519.Point{public_key}, []ed25519.Point{encrypted_share}, []ed25519.Scalar{secret_key})

	return ShareDecryptionProof{challenge, response}
}

// """ Check that the given share does indeed correspond to the given encrypted share.
// Returns True if the share is valid.
// """

func Verify_decrypted_share(decrypted_share ed25519.Point, encrypted_share ed25519.Point, public_key ed25519.Point, proof ShareDecryptionProof) bool {
	challenge, response := proof.challenge, proof.response
	return DLEQ_verify([]ed25519.Point{H}, []ed25519.Point{decrypted_share}, []ed25519.Point{public_key}, []ed25519.Point{encrypted_share}, challenge, response)

}

// """ Takes EXACTLY t (idx, decrypted_share) tuples and performs Langrange interpolation to recover the secret S.
//         The validity of the decrypted shares has to be verified prior to a call of this function.
//     """
// TODO: Take in indices of shares instead of recovery threshold
// NOTE: Indices of shares are [1 ... recovery_threshold]
func Recover(decrypted_shares []ed25519.Point, recovery_threshold int) ed25519.Point {
	var idxs []ed25519.Scalar
	for i := 1; i <= recovery_threshold; i++ {
		idxs = append(idxs, ed25519.New_scalar(*big.NewInt(int64(i))))
	}
	var rec ed25519.Point
	rec = ed25519.B // initialing it, will be subtracted later

	for idx := 0; idx < recovery_threshold; idx++ {
		t := Lagrange_coeffecient(ed25519.New_scalar(*big.NewInt(int64(idx + 1))), idxs)
		a := decrypted_shares[idx].Mul(t)
		rec = rec.Add(a)
	}
	rec = rec.Sub(ed25519.B)
	return rec
}

func Random_codeword(num_nodes int, recovery_threshold int) []ed25519.Scalar {
	var codeword []ed25519.Scalar
	f := Random(num_nodes - recovery_threshold - 1)

	for i := 1; i <= num_nodes; i++ {
		vi := ed25519.New_scalar(*big.NewInt(1))

		for j := 1; j <= num_nodes; j++ {
			if j != i {
				numerator := new(big.Int).Sub(big.NewInt(int64(i)), big.NewInt(int64(j)))
				// fmt.Println(new(big.Int).Mod(numerator,ed25519.GROUP_ORDER))
				vi = vi.Mul(ed25519.New_scalar(*new(big.Int).Mod(numerator, ed25519.GROUP_ORDER)))
			}
		}

		vi.Invert()
		// x,_ :=ed25519.Scalar_from_bytes(vi.Val)

		codeword = append(codeword, vi.Mul(f.Eval(i)))

	}
	return codeword
}

func Lagrange_coeffecient(i ed25519.Scalar, indexes []ed25519.Scalar) ed25519.Scalar {
	numerator := ed25519.New_scalar(*big.NewInt(1))
	denominator := ed25519.New_scalar(*big.NewInt(1))
	for j := 0; j < len(indexes); j++ {
		if indexes[j].Not_equal(i) {
			numerator = numerator.Mul(indexes[j])
			denominator = denominator.Mul(indexes[j].Sub(i))
		}
	}
	return numerator.Div(denominator)
}

// func hello() (ed25519.Point) {
// 	return ed25519.Point_one()
// }
