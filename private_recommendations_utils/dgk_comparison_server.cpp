/*
SeComLib
Copyright 2012-2013 TU Delft, Information Security & Privacy Lab (http://isplab.tudelft.nl/)

Contributors:
Inald Lagendijk (R.L.Lagendijk@TUDelft.nl)
Mihai Todor (todormihai@gmail.com)
Thijs Veugen (P.J.M.Veugen@tudelft.nl)
Zekeriya Erkin (z.erkin@tudelft.nl)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/**
@file private_recommendations_utils/dgk_comparison_server.cpp
@brief Implementation of class DgkComparisonServer.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "dgk_comparison_server.h"
//avoid circular includes
#include "dgk_comparison_client.h"

namespace SeComLib {
namespace PrivateRecommendationsUtils {
	/**
	@param paillierCryptoProvider the Paillier crypto provider
	@param dgkCryptoProvider the DGK crypto provider
	@param l bitsize of the multiplication operands
	*/
	DgkComparisonServer::DgkComparisonServer (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const size_t l) :
		paillierCryptoProvider(paillierCryptoProvider),
		dgkCryptoProvider(dgkCryptoProvider),
		l(l) {
	}

	/**
	Algorithm: @f$ t_{i + 1} = (1 - (a_i - b_i)^2) t_i + a_i (1 - b_i) @f$, for @f$ 0 \leq i < l + 1 @f$

	@note In the paper, in Appendix C., it is stated that @f$ i < l + 1 @f$, but in D., @f$ a @f$ and @f$ b @f$ are @f$ l @f$ bit numbers. This is due to the data packing requirements, so l will be l + 1 for the data packing version

	@param rModTwoPowL @f$ r \pmod 2^l @f$
	@return encrypted result of the comparison: @f$ [0] @f$ or @f$ [1] @f$
	*/
	Paillier::Ciphertext DgkComparisonServer::Compare (const BigInteger &rModTwoPowL) const {
		BigInteger c = RandomProvider::GetInstance().GetRandomInteger(1);

		Dgk::Ciphertext tau = this->computeTau(rModTwoPowL, c);

		/// Compute @f$ t_l = t_{PSP} \oplus t_{SP} @f$
		Dgk::Ciphertext tl;
		/// @f$ t_{PSP} = \tau @f$ and @f$ t_{SP} = c @f$
		if (c == 0) {
			/// @f$ [t_l] = [t_{PSP}] @f$
			tl = tau;
		}
		else {
			/// @f$ [t_l] = [1] [t_PSP]^{-1} \pmod n @f$
			tl = this->dgkCryptoProvider.GetEncryptedOne(false) - tau;
		}

		/// Randomize @f$ \llbracket t_l \rrbracket @f$ and interact with the client to convert it to a Paillier encryption
		tl = this->dgkCryptoProvider.RandomizeCiphertext(tl);
		return this->dgkComparisonClient.lock()->ConvertToPaillier(tl);
	}

	/**
	@param ri @f$ r_{l + 1}^{(i)} @f$
	@return @f$ [d^{(i)}] @f$
	*/
	Paillier::Ciphertext DgkComparisonServer::ComputeDi (const BigInteger &ri) const {
		BigInteger CiSP = RandomProvider::GetInstance().GetRandomInteger(1);

		/// @f$ \llbracket C_{i(l + 2) + (l + 1)}^{PSP} \rrbracket = \llbracket \tau \rrbracket @f$
		Dgk::Ciphertext CiPSP = this->computeTau(ri, CiSP);

		/// Randomize @f$ \llbracket C_{i(l + 2) + (l + 1)}^{PSP} \rrbracket @f$
		CiPSP = this->dgkCryptoProvider.RandomizeCiphertext(CiPSP);

		/// @f$ [d_{l + 1}^{(i, PSP)}] = [z_{l + 1}^{(i)} \oplus C_{i(l + 2) + (l + 1)}^{PSP}] @f$
		Paillier::Ciphertext diPSP = this->dgkComparisonClient.lock()->ComputeDiPSP(CiPSP);

		/// @f$ [d_{l + 1}^{(i, SP)}] = [r_{l + 1}^{(i)} \oplus C_{i(l + 2) + (l + 1)}^{SP}] @f$
		int diSP;
		if (CiSP != static_cast<long>(ri.GetBit(this->GetMSBPosition()))) {
			diSP = 1;
		}
		else {
			diSP = 0;
		}

		/// @f$ [d_{l + 1}^{(i)}] = [d_{l + 1}^{(i, PSP)} \oplus d_{l + 1}^{(i, PSP)}] @f$
		if (diSP == 0) {
			return diPSP;
		}
		else {
			/// @f$ [d_{l + 1}^{(i)}] = [1] [d_{l + 1}^{(i, PSP)}]^{-1} \pmod n @f$
			return this->paillierCryptoProvider.GetEncryptedOne(false) - diPSP;
		}
	}

	/**
	@param a alias for @f$ [r \pmod 2^l] @f$
	@param tSP the additive share of the Server, denoted as @f$ c @f$ in the protocol
	@return Unrandomized @f$ [\tau] @f$
	*/
	Dgk::Ciphertext DgkComparisonServer::computeTau (const BigInteger &a, const BigInteger &tSP) const {
		Dgk::Ciphertext b0 = this->dgkComparisonClient.lock()->GetBi(0);

		Dgk::Ciphertext t;

		/// If @f$ a_0 = 0 @f$
		if (a.GetBit(0) == 0) {
			/// @f$ \llbracket t \rrbracket = \llbracket 0 \rrbracket @f$
			t = this->dgkCryptoProvider.GetEncryptedZero(false);
		}
		else {
			/// @f$ \llbracket t \rrbracket = \llbracket 1 \rrbracket \llbracket b_0 \rrbracket^{-1} \pmod n @f$
			t = this->dgkCryptoProvider.GetEncryptedOne(false) - b0;
		}

		/// @f$ i = 1 : l - 1 @f$
		for (size_t i = 1; i < this->l; ++i) {
			/// Blind @f$ t = t_i @f$ by tossing a fair coin @f$ c \in {-1, 1} @f$
			BigInteger c = RandomProvider::GetInstance().GetRandomInteger(1);

			Dgk::Ciphertext tau;
			
			//perform blinding
			if (c == 0) {
				/// @f$ \llbracket \tau \rrbracket = \llbracket t \rrbracket @f$
				tau = t;
			}
			else {
				/// @f$ \llbracket \tau \rrbracket = \llbracket 1 \rrbracket \llbracket t \rrbracket^{-1} \pmod n @f$
				tau = this->dgkCryptoProvider.GetEncryptedOne(false) - t;
			}

			/// Randomize @f$ \llbracket \tau \rrbracket @f$
			tau = this->dgkCryptoProvider.RandomizeCiphertext(tau);

			/// Fetch @f$ \llbracket tb \rrbracket @f$
			Dgk::Ciphertext tb = this->dgkComparisonClient.lock()->GetTb(tau, i);

			/// Fetch @f$ \llbracket b_i \rrbracket @f$
			Dgk::Ciphertext bi = this->dgkComparisonClient.lock()->GetBi(i);

			/// If @f$ c = 1 @f$
			if (c == 1) {
				/// @f$ \llbracket tb \rrbracket = \llbracket b_i \rrbracket \llbracket tb \rrbracket^{-1} \pmod n @f$
				tb = bi - tb;
			}

			if (a.GetBit(i) == 0) {
				/// @f$ \llbracket t \rrbracket = \llbracket t \rrbracket \llbracket tb \rrbracket^{-1} \pmod n @f$
				t = t - tb;
			}
			else {
				/// @f$ \llbracket t \rrbracket = \llbracket tb \rrbracket \llbracket 1 \rrbracket \llbracket b_i \rrbracket^{-1} \pmod n @f$
				t = tb + (this->dgkCryptoProvider.GetEncryptedOne(false) - bi);
			}
		}
		
		/// Blind @f$ t = t_l @f$ by tossing a fair coin @f$ c \in {-1, 1} @f$
		if (tSP == 0) {
			/// @f$ \llbracket \tau \rrbracket = \llbracket t \rrbracket @f$
			return t;
		}
		else {
			/// @f$ \llbracket \tau \rrbracket = \llbracket 1 \rrbracket \llbracket t \rrbracket^{-1} \pmod n @f$
			return this->dgkCryptoProvider.GetEncryptedOne(false) - t;
		}
	}

	/**
	@return @f$ l @f$
	*/
	size_t DgkComparisonServer::GetMSBPosition () const {
		return this->l;
	}

	/**
	@param dgkComparisonClient a DgkComparisonClient instance
	*/
	void DgkComparisonServer::SetClient (const std::shared_ptr<DgkComparisonClient> &dgkComparisonClient) {
		this->dgkComparisonClient = dgkComparisonClient;
	}

}//namespace PrivateRecommendationsUtils
}//namespace SeComLib