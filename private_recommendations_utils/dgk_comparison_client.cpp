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
@file private_recommendations_utils/dgk_comparison_client.cpp
@brief Implementation of class DgkComparisonClient.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "dgk_comparison_client.h"
//avoid circular includes
#include "dgk_comparison_server.h"

namespace SeComLib {
namespace PrivateRecommendationsUtils {
	/**
	@param paillierCryptoProvider the Paillier crypto provider
	@param dgkCryptoProvider the Dgk crypto provider
	*/
	DgkComparisonClient::DgkComparisonClient (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider) :
		paillierCryptoProvider(paillierCryptoProvider),
		dgkCryptoProvider(dgkCryptoProvider) {
	}

	/**
	@param zModTwoPowL @f$ z \pmod 2^l @f$
	*/
	void DgkComparisonClient::SetZModTwoPowL (const BigInteger &zModTwoPowL) {
		this->b = zModTwoPowL;
	}

	/**
	@param tau @f$ \llbracket \tau \rrbracket @f$
	@param i the bit index of @f$ b @f$
	@return @f$ \llbracket tb \rrbracket @f$
	*/
	Dgk::Ciphertext DgkComparisonClient::GetTb (const Dgk::Ciphertext &tau, const size_t i) const {
		Dgk::Ciphertext tb;

		/// If @f$ b_i = 0 @f$
		if (this->b.GetBit(i) == 0) {
			/// @f$ \llbracket tb \rrbracket = \llbracket 0 \rrbracket @f$
			tb = this->dgkCryptoProvider.GetEncryptedZero(false);
		}
		else {
			// @f$ \llbracket tb \rrbracket = \llbracket \tau \rrbracket @f$
			tb = tau;
		}

		tb = this->dgkCryptoProvider.RandomizeCiphertext(tb);

		return tb;
	}

	/**
	@param i the bit index
	@return @f$ \llbracket b_i \rrbracket @f$
	*/
	Dgk::Ciphertext DgkComparisonClient::GetBi (const size_t i) const {
		return this->dgkCryptoProvider.EncryptInteger(BigInteger(static_cast<long>(this->b.GetBit(i))));
	}

	/**
	@param dgkCiphertext @f$ \llbracket dgkPlaintext \rrbracket @f$
	@return @f$ [\tau] @f$
	*/
	Paillier::Ciphertext DgkComparisonClient::ConvertToPaillier (const Dgk::Ciphertext &dgkCiphertext) const {
		/// Since @f$ \tau \in {0, 1} @f$, we can skip the table lookup required to do a full decryption
		if (this->dgkCryptoProvider.IsEncryptedZero(dgkCiphertext)) {
			return this->paillierCryptoProvider.GetEncryptedZero();
		}
		else {
			return this->paillierCryptoProvider.GetEncryptedOne();
		}
	}

	/**
	@param CiPSP @f$ \llbracket C_{i(l + 2) + (l + 1)}^{PSP} \rrbracket @f$
	@return @f$ [d_{l + 1}^{(i, PSP)}] @f$
	*/
	Paillier::Ciphertext DgkComparisonClient::ComputeDiPSP (const Dgk::Ciphertext &CiPSP) const {
		int decryptedCiPSP;
		if (this->dgkCryptoProvider.IsEncryptedZero(CiPSP)) {
			decryptedCiPSP = 0;
		}
		else {
			decryptedCiPSP = 1;
		}

		/// @f$ [d_{l + 1}^{(i, PSP)}] = [z_{l + 1}^{(i)} \oplus C_{i(l + 2) + (l + 1)}^{PSP}] @f$
		int diPSP = this->b.GetBit(this->dgkComparisonServer->GetMSBPosition()) ^ decryptedCiPSP;

		if (diPSP == 0) {
			return this->paillierCryptoProvider.GetEncryptedZero();
		}
		else {
			return this->paillierCryptoProvider.GetEncryptedOne();
		}
	}

	/**
	@param dgkComparisonServer a DgkComparisonServer instance
	*/
	void DgkComparisonClient::SetServer (const std::shared_ptr<DgkComparisonServer> &dgkComparisonServer) {
		this->dgkComparisonServer = dgkComparisonServer;
	}

	/**
	@param input a DGK encrypted integer
	*/
	void DgkComparisonClient::DebugDgkEncryption (const Dgk::Ciphertext &input) const {
		std::cout << !this->dgkCryptoProvider.IsEncryptedZero(input) << std::endl;
	}

}//namespace PrivateRecommendationsUtils
}//namespace SeComLib