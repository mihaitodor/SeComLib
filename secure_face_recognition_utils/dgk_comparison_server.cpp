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
@file secure_face_recognition_utils/dgk_comparison_server.cpp
@brief Implementation of class DgkComparisonServer.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "dgk_comparison_server.h"
//avoid circular includes
#include "dgk_comparison_client.h"

namespace SeComLib {
namespace SecureFaceRecognitionUtils {
	/**
	@param paillierCryptoProvider the Paillier crypto provider
	@param dgkCryptoProvider the DGK crypto provider
	@param configurationPath the configuration path for parameters
	*/
	DgkComparisonServer::DgkComparisonServer (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const std::string &configurationPath) :
		paillierCryptoProvider(paillierCryptoProvider),
		dgkCryptoProvider(dgkCryptoProvider),
		l(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".l")),
		encryptedMinusTwoPowL(paillierCryptoProvider.EncryptIntegerNonrandom(BigInteger(-1) << static_cast<unsigned long>(l))),
		blindingFactorCache(dgkCryptoProvider, DgkComparisonBlindingFactorCacheParameters(configurationPath, l + 1)) {
	}
	
	/**

	@param hatRBits the bits of @f$ \hat{r} @f$
	@param s random value @f$ s \in {0, 1} @f$
	@return @f$ \lambda @f$
	*/
	Paillier::Ciphertext DgkComparisonServer::ComputeLambda (const std::deque<long> &hatRBits, const BigInteger &s) {
		/// Implementation of Protocol 4.10, as described in Martin Franz' Master Thesis from 2008 (@f$ a = [\hat{d}] @f$, @f$ b = \hat{r} @f$

		/// Fetch @f$ \hat{d} @f$ from the client
		std::deque<Dgk::Ciphertext> hatDBits = this->dgkComparisonClient.lock()->GetHatDBits();

		const BlindingFactorContainer &blindingFactorContainer = this->blindingFactorCache.Pop();

		/// Compute the @f$ e @f$ vector
		std::deque<Dgk::Ciphertext> e;

		/// If @f$ \hat{r}_{l - 1} = s @f$
		if (s == hatRBits[l - 1]) {
			/// @warning Protocol 4.10 from Martin Franz' Master Thesis DOES NOT take into account the two different cases when @f$ \hat{r}_{l - 1} = 0 @f$ and @f$ \hat{r}_{l - 1} = 1 @f$ so the protocol does not work properly for values that differ starting with the MSB!

			/// @f$ [e_{l - 1}] = [0] @f$ if @f$ (d_{l - 1} < r_{l - 1}) \land s = 1 @f$ or if @f$ (d_{l - 1} > r_{l - 1}) \land s = 0 @f$
			if (hatRBits[l - 1] == 0) {
				/// @f$ [e_{l - 1}] = [\hat{d}_{l - 1} - 1]^{R_{l - 1}}) = (([\hat{d}_{l - 1}] [1]^{-1})^{R_{l - 1}}) @f$
				e.emplace_front((hatDBits[l - 1] - this->dgkCryptoProvider.GetEncryptedOne(false)) * blindingFactorContainer.R[l]);
			}
			else {
				/// @f$ [e_{l - 1}] = ([\hat{d}_{l - 1}]^{R_{l - 1}}) @f$
				e.emplace_front(hatDBits[l - 1] * blindingFactorContainer.R[l]);//the indexes in R are shifted by one
			}
			/// @f$ [e_{l - 1}] = [e_{l - 1}]_{re-rand} @f$
			e.front() = this->dgkCryptoProvider.RandomizeCiphertext(e.front());
		}
		else {
			/// @f$ [e_{l - 1}] = [R_{l-1}] @f$
			e.emplace_front(blindingFactorContainer.encryptedR[l]);//the indexes in encryptedR are shifted by one
		}

		/// @f$ [\sigma] = xor([\hat{d}_{l - 1}], \hat{r}_{l - 1}) @f$
		Dgk::Ciphertext sigma = hatRBits[l - 1] == 0 ? hatDBits[l - 1] : (this->dgkCryptoProvider.GetEncryptedOne(false) - hatDBits[l - 1]);
		//can't use size_t because the stop condition requires i = -1
		for (long i = static_cast<long>(this->l - 2); i >= 0; --i) {
			/// If @f$ b_i = s @f$
			if (s == hatRBits[i]) {
				/// @f$ [c] = [\hat{d}_{i} + \sigma] = [\hat{d}_{i}] [\sigma] @f$
				Dgk::Ciphertext c = hatDBits[i] + sigma;
				
				if (s == 0) {
					/// @f$ [c] = [c - 1 + \sigma] = [c] [-1] [\sigma] @f$
					c = c - this->dgkCryptoProvider.GetEncryptedOne(false) + sigma;
				}

				/// @f$ [e_i] = ([c]^{R_i})_{re-rand}@f$
				e.emplace_front(c * blindingFactorContainer.R[i + 1]);//the indexes in R are shifted by one
				e.front() = this->dgkCryptoProvider.RandomizeCiphertext(e.front());
			}
			else {
				/// @f$ [e_i] = [R_i] @f$
				e.emplace_front(blindingFactorContainer.encryptedR[i + 1]);//the indexes in encryptedR are shifted by one
			}
			
			/// @f$ [\sigma] = [\sigma] xor([\hat{d}_{i}], \hat{r}_{i}) @f$
			sigma = sigma + (hatRBits[i] == 0 ? hatDBits[i] : (this->dgkCryptoProvider.GetEncryptedOne(false) - hatDBits[i]));
		}

		/**
		To avoid the case @f$ \hat{d} = \hat{r} @f$, we compare @f$ 2 \hat{d} + 1 @f$ and @f$ 2 \hat{r} @f$ instead (append differing bits that don't change the final result)
		Due to this, @f$ 2 \hat{d} + 1 @f$ and @f$ 2 \hat{r} @f$ will have (at most) @f$ l + 1 @f$ bits

		In order to achieve this, we know the values of the new LSB of @f$ \hat{d} @f$ and @f$ \hat{r} @f$: @f$ LSB(\hat{d}) = 1 @f$ and @f$ LSB(\hat{r}) = 0 @f$
		*/

		if (s == 1) {
			/// @f$ [e_{-1}] = [R_{-1}] @f$
			e.emplace_front(blindingFactorContainer.encryptedR[0]);//the indexes in encryptedR are shifted by one
		}
		else {
			/// @f$ [e_{-1}] = ([\sigma]^{R_{-1}})_{re-rand}@f$
			e.emplace_front(sigma * blindingFactorContainer.R[0]);//the indexes in R are shifted by one
			e.front() = this->dgkCryptoProvider.RandomizeCiphertext(e.front());//is this really necessary?
		}

		/// Apply a random permutation to vector @f$ e @f$
		SecurePermutation permutation(e.size());
		permutation.Permute(e);

		Paillier::Ciphertext lambda = this->dgkComparisonClient.lock()->ComputeLambda(e);

		if (s == 0) {
			/// @f$ [\lambda] = [-2^l] [\lambda]^{-1} @f$
			lambda = this->encryptedMinusTwoPowL - lambda;
		}

		return lambda;
	}

	/**
	@param dgkComparisonClient a DgkComparisonClient instance
	*/
	void DgkComparisonServer::SetClient (const std::shared_ptr<DgkComparisonClient> &dgkComparisonClient) {
		this->dgkComparisonClient = dgkComparisonClient;
	}

}//namespace SecureFaceRecognitionUtils
}//namespace SeComLib