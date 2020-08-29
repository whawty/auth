//
// Copyright (c) 2016 whawty contributors (see AUTHORS file)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of whawty.auth nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/nbutton23/zxcvbn-go"
	"github.com/nbutton23/zxcvbn-go/scoring"
)

type zxcvbnPolicy struct {
	condition func(score scoring.MinEntropyMatch, threshold uint64) bool
	threshold uint64
}

func (z zxcvbnPolicy) Check(password, username string) (result bool, err error) {
	score := zxcvbn.PasswordStrength(password, []string{username, "whawty"})
	result = z.condition(score, z.threshold)
	if result {
		wdl.Printf("zxcbvn result: score = %d, entropy = %f, crack-time: %s (%f s) -> success", score.Score, score.Entropy, score.CrackTimeDisplay, score.CrackTime)
	} else {
		wdl.Printf("zxcbvn result: score = %d, entropy = %f, crack-time: %s (%f s) -> failed", score.Score, score.Entropy, score.CrackTimeDisplay, score.CrackTime)
	}
	return result, nil
}

func zxcvbnConditionScore(score scoring.MinEntropyMatch, threshold uint64) bool {
	return score.Score >= int(threshold)
}

func zxcvbnConditionEntropy(score scoring.MinEntropyMatch, threshold uint64) bool {
	return score.Entropy >= float64(threshold)
}

func zxcvbnConditionTime(score scoring.MinEntropyMatch, threshold uint64) bool {
	return score.CrackTime >= float64(threshold)
}

func newZXCVBNPolicy(condition string) (p zxcvbnPolicy, err error) {
	c := strings.Fields(condition)
	if len(c) != 3 {
		err = fmt.Errorf("invalid policy condition string '%s'", condition)
		return
	}

	if c[1] != ">=" {
		err = fmt.Errorf("condition may only check for '>='")
		return
	}

	if p.threshold, err = strconv.ParseUint(c[2], 10, 64); err != nil {
		return
	}

	switch c[0] {
	case "score":
		if p.threshold > 4 {
			err = fmt.Errorf("threshold %d is too high for zxcvbn.score, must be <= 4", p.threshold)
			return
		}
		p.condition = zxcvbnConditionScore
	case "entropy":
		p.condition = zxcvbnConditionEntropy
	case "time":
		p.condition = zxcvbnConditionTime
	default:
		err = fmt.Errorf("invalid condition value '%s', must be one of score, entropy, time", c[0])
		return
	}
	return
}

type nullPolicy struct {
}

func (z nullPolicy) Check(password, username string) (result bool, err error) {
	return true, nil
}

type PolicyChecker interface {
	Check(password, username string) (bool, error)
}

func NewPasswordPolicy(policyType, condition string) (p PolicyChecker, err error) {
	switch policyType {
	case "":
		return nullPolicy{}, nil
	case "zxcvbn":
		return newZXCVBNPolicy(condition)
	default:
		return nil, fmt.Errorf("unknown password-policy type: %s", policyType)
	}
}
