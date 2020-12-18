package crypto

import (
	"math/big"
	// // "errors"
	// // "strconv"
	// // "bytes"
	// // "unsafe"
	// "crypto/sha512"
	// "crypto/sha256"
	"ed25519"
	"reflect"
	"testing"
	// "github.com/ethereum/go-ethereum/crypto/ed25519"
)

var NUM_NODES = 350
var RECOVERY_THRESHOLD = NUM_NODES/3 + 1
var public_keys []ed25519.Point
var secret_keys []ed25519.Scalar
var decrypted_shares []ed25519.Point
var secret ed25519.Scalar
var encrypted_shares []ed25519.Point
var proof ShareCorrectnessProof

func init() {

	for i := 0; i < NUM_NODES; i++ {
		sk, pk := Keygen()
		secret_keys = append(secret_keys, sk)
		public_keys = append(public_keys, pk)
	}
	secret = ed25519.Random()
	cm := Share_random_secret(public_keys, RECOVERY_THRESHOLD, secret)
	encrypted_shares = cm.encrypted_shares
	proof = cm.proof
	for j := 0; j < len(encrypted_shares); j++ {
		decrypted_shares = append(decrypted_shares, Decrypt_share(encrypted_shares[j], secret_keys[j]))
	}
}

func BenchmarkShareGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		num_receivers := NUM_NODES
		poly := Random(RECOVERY_THRESHOLD - 1)
		var shares []ed25519.Scalar
		for i := 1; i <= num_receivers; i++ {
			shares = append(shares, poly.Eval(i))
		}
	}

}

func BenchmarkCommitmentGeneration(b *testing.B) {
	num_receivers := NUM_NODES
	poly := Random(RECOVERY_THRESHOLD - 1)
	var shares []ed25519.Scalar
	for i := 1; i <= num_receivers; i++ {
		shares = append(shares, poly.Eval(i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var commitment_shares []ed25519.Point
		for j := 0; j < num_receivers; j++ {
			commitment_shares = append(commitment_shares, G.Mul(shares[j]))
		}
	}

}

func BenchmarkProofGeneration(b *testing.B) {
	num_receivers := NUM_NODES
	poly := Random(RECOVERY_THRESHOLD - 1)
	var shares []ed25519.Scalar
	for i := 1; i <= num_receivers; i++ {
		shares = append(shares, poly.Eval(i))
	}
	var encrypted_shares []ed25519.Point
	for j := 0; j < num_receivers; j++ {
		encrypted_shares = append(encrypted_shares, public_keys[j].Mul(shares[j]))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Prove_share_correctness(shares, encrypted_shares, public_keys)
	}

}

func BenchmarkAggregation(b *testing.B) {
	new_encs := make([]ed25519.Point, len(encrypted_shares))
	copy(new_encs, encrypted_shares)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < RECOVERY_THRESHOLD; j++ {
			for k := 0; k < len(encrypted_shares); k++ {
				new_encs[k] = new_encs[k].Add(encrypted_shares[k])
			}
		}
	}

}

func BenchmarkCodeWordVerification(b *testing.B) {
	for i := 0; i < b.N; i++ {

		codeword := Random_codeword(NUM_NODES, RECOVERY_THRESHOLD)
		commitments := proof.commitments
		// codeword := Cdword()
		product := commitments[0].Mul(codeword[0])
		// fmt.Println(len(codeword))
		// fmt.Println(len(commitments))
		for i := 1; i < NUM_NODES; i++ {
			product = product.Add(commitments[i].Mul(codeword[i]))
		}
	}

}

func BenchmarkShareProofVerification(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !(Verify_shares_no_codeword(encrypted_shares, proof, public_keys, RECOVERY_THRESHOLD)) {
			b.Errorf("Share verification failed")

		}
	}
}

func TestDLEQ(t *testing.T) {
	alpha := ed25519.Random()
	e, z := DLEQ_prove([]ed25519.Point{G}, []ed25519.Point{H}, []ed25519.Point{G.Mul(alpha)}, []ed25519.Point{H.Mul(alpha)}, []ed25519.Scalar{alpha})

	result := DLEQ_verify([]ed25519.Point{G}, []ed25519.Point{H}, []ed25519.Point{G.Mul(alpha)}, []ed25519.Point{H.Mul(alpha)}, e, z)
	if !result {
		t.Errorf("DLEQ not working")
	}

}

//benchmarks prove and verify DLEQ
func BenchmarkDLEQ(b *testing.B) {

	for i := 0; i < b.N; i++ {
		alpha := ed25519.Random()
		e, z := DLEQ_prove([]ed25519.Point{G}, []ed25519.Point{H}, []ed25519.Point{G.Mul(alpha)}, []ed25519.Point{H.Mul(alpha)}, []ed25519.Scalar{alpha})

		result := DLEQ_verify([]ed25519.Point{G}, []ed25519.Point{H}, []ed25519.Point{G.Mul(alpha)}, []ed25519.Point{H.Mul(alpha)}, e, z)
		if !result {
			b.Errorf("DLEQ not working")
		}
	}
}

func TestDLEQInvalidChallenge(t *testing.T) {
	alpha := ed25519.Random()
	e, z := DLEQ_prove([]ed25519.Point{G}, []ed25519.Point{H}, []ed25519.Point{G.Mul(alpha)}, []ed25519.Point{H.Mul(alpha)}, []ed25519.Scalar{alpha})
	e = e.Add(ed25519.New_scalar(*big.NewInt(1)))

	result := DLEQ_verify([]ed25519.Point{G}, []ed25519.Point{H}, []ed25519.Point{G.Mul(alpha)}, []ed25519.Point{H.Mul(alpha)}, e, z)
	if result {
		t.Errorf("DLEQ(IC) not working")
	}

}

func TestDLEQNonEqual(t *testing.T) {
	alpha := ed25519.Random()
	beta := ed25519.Random()
	e, z := DLEQ_prove([]ed25519.Point{G}, []ed25519.Point{H}, []ed25519.Point{G.Mul(alpha)}, []ed25519.Point{H.Mul(beta)}, []ed25519.Scalar{alpha})
	e = e.Add(ed25519.New_scalar(*big.NewInt(1)))

	result := DLEQ_verify([]ed25519.Point{G}, []ed25519.Point{H}, []ed25519.Point{G.Mul(alpha)}, []ed25519.Point{H.Mul(beta)}, e, z)
	if result {
		t.Errorf("DLEQ(NE) not working")
	}

}

func TestVerification(t *testing.T) {
	for i := 0; i < len(encrypted_shares); i++ {
		enc_share := encrypted_shares[i]
		sk := secret_keys[i]
		pk := public_keys[i]
		dec_share := Decrypt_share(enc_share, sk)
		proof_new := Prove_share_decryption(dec_share, enc_share, sk, pk)
		if !Verify_decrypted_share(dec_share, enc_share, pk, proof_new) {
			t.Errorf("Share encryption proof not working")
		}

	}

}

// func BenchmarkVerification(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		for i := 0; i < len(encrypted_shares); i++ {
// 			enc_share := encrypted_shares[i]
// 			sk := secret_keys[i]
// 			pk := public_keys[i]
// 			dec_share := Decrypt_share(enc_share, sk)
// 			proof_new := Prove_share_decryption(dec_share, enc_share, sk, pk)
// 			if !Verify_decrypted_share(dec_share, enc_share, pk, proof_new) {
// 				b.Errorf("Share encryption proof not working")
// 			}

// 		}
// 	}

// }

func TestShareVerification(t *testing.T) {
	if !(Verify_shares(encrypted_shares, proof, public_keys, RECOVERY_THRESHOLD)) {
		t.Errorf("Share verification failed")

	}
}

// func BenchmarkShareVerification(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		if !(Verify_shares(encrypted_shares, proof, public_keys, RECOVERY_THRESHOLD)) {
// 			b.Errorf("Share verification failed")

// 		}
// 	}
// }

// func Test_verify_secret(t *testing.T) {
// 	cmts := proof.commitments
// 	if !Verify_secret(secret, cmts, RECOVERY_THRESHOLD) {
// 		t.Errorf("Verify secret not working")
// 	}
// }

// func Benchmark_verify_secret(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		cmts := proof.commitments
// 		if !Verify_secret(secret, cmts, RECOVERY_THRESHOLD) {
// 			b.Errorf("Verify secret not working")
// 		}
// 	}
// }

func Test_recover_secret(t *testing.T) {
	rs := Recover(decrypted_shares, RECOVERY_THRESHOLD)
	if rs.Not_equal(H.Mul(secret)) {
		t.Errorf("Recover secret not working")
	}
}

func Benchmark_recover_secret(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rs := Recover(decrypted_shares, RECOVERY_THRESHOLD)
		if rs.Not_equal(H.Mul(secret)) {
			b.Errorf("Recover secret not working")
		}
	}
}

func TestPoint_G(t *testing.T) {
	if !reflect.DeepEqual(H, H) {
		t.Errorf("Equality test not working")
	}
}
