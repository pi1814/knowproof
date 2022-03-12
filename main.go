package main

import (
    "fmt"
    "go.dedis.ch/kyber/v3"
    "go.dedis.ch/kyber/v3/group/edwards25519"
    "go.dedis.ch/kyber/v3/proof"
    "encoding/hex"
)

func main() {
    
    
    suite := edwards25519.NewBlakeSHA256Ed25519()
    rand := suite.RandomStream()

    x := suite.Scalar().Pick(rand)
    y := suite.Scalar().Pick(rand)
    B := suite.Point().Base()
    X := suite.Point().Mul(x, nil)
    Y := suite.Point().Mul(y, nil)
    R := suite.Point().Add(X, Y)
    
    
    fmt.Printf("X=xB and Y=yB and R=xB+yB\n")
    fmt.Printf("x=%s, B=%s, X=%s, y=%s, Y=%s, R=%s\n\n",x,B,X,y,Y,R)

    // X = xB
    pred := proof.Rep("X", "x", "B")
    fmt.Println(pred.String())


    sval := map[string]kyber.Scalar{"x": x}
    pval := map[string]kyber.Point{"B": B, "X": X}

    prover := pred.Prover(suite, sval, pval, nil)
    proof_, _ := proof.HashProve(suite, "TEST", prover)

    fmt.Printf("We need to prove that we known the discrete log of X\n")
    fmt.Print("Proof:\n" + hex.Dump(proof_))

    
    // Verify this knowledge proof.
    verifier := pred.Verifier(suite, pval)
    err := proof.HashVerify(suite, "TEST", verifier, proof_)
    if err != nil {
        fmt.Println("Proof failed to verify: ", err)
        return
    }
    fmt.Println("-- Proof verified.\n")


    pred = proof.Rep("R", "x", "B","y", "B")
    fmt.Println(pred.String())

    sval = map[string]kyber.Scalar{"x": x,"y": y}
    pval = map[string]kyber.Point{"B": B, "R": R}
    prover = pred.Prover(suite, sval, pval, nil)
    proof_, _ = proof.HashProve(suite, "TEST", prover)
    fmt.Print("Proof:\n" + hex.Dump(proof_))
    verifier = pred.Verifier(suite, pval)
    err = proof.HashVerify(suite, "TEST", verifier, proof_)
    if err != nil {
        fmt.Println("Proof failed to verify: ", err)
        return
    }

    fmt.Println("-- Proof verified.\n")


 //   pred = proof.Rep("Y", "y", "B") - Correct
     pred = proof.Rep("X", "y", "B")
    fmt.Println(pred.String())

    sval = map[string]kyber.Scalar{"y": y}
    pval = map[string]kyber.Point{"B": B, "Y": Y}
    prover = pred.Prover(suite, sval, pval, nil)
    proof_, _ = proof.HashProve(suite, "TEST", prover)
    fmt.Print("Proof:\n" + hex.Dump(proof_))
    verifier = pred.Verifier(suite, pval)
    err = proof.HashVerify(suite, "TEST", verifier, proof_)
    if err != nil {
        fmt.Println("Proof failed to verify: ", err)
        return
    }

    fmt.Println("-- Proof verified.")
}
