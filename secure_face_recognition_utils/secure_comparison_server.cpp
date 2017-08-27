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
@file secure_face_recognition_utils/secure_comparison_server.cpp
@brief Implementation of class SecureComparisonServer.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "secure_comparison_server.h"
//avoid circular includes
#include "secure_comparison_client.h"

namespace SeComLib {
namespace SecureFaceRecognitionUtils {
	/**
	@param paillierCryptoProvider the Paillier crypto provider
	@param dgkCryptoProvider the DGK crypto provider
	@param configurationPath the configuration path for parameters
	*/
	SecureComparisonServer::SecureComparisonServer (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const std::string &configurationPath) :
		paillierCryptoProvider(paillierCryptoProvider),
		dgkCryptoProvider(dgkCryptoProvider),
		dgkComparisonServer(std::make_shared<DgkComparisonServer>(paillierCryptoProvider, dgkCryptoProvider, configurationPath)),
		l(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".l")),
		twoPowL(BigInteger(2).GetPow(static_cast<unsigned long>(l))),
		twoPowMinusLModN(BigInteger(2).GetPowModN(-(static_cast<long>(l)), paillierCryptoProvider.GetEncryptionModulus())),
		encryptedTwoPowL(paillierCryptoProvider.EncryptInteger(twoPowL)),
		blindingFactorCache(paillierCryptoProvider, ComparisonBlindingFactorCacheParameters(configurationPath, l)) {
	}

	/**
	@param a encrypted left hand side operand
	@param b encrypted right hand side operand
	@return @f$ [a] \leq [b] ? [1] : [0] @f$
	*/
	Paillier::Ciphertext SecureComparisonServer::Compare (const Paillier::Ciphertext &a, const Paillier::Ciphertext &b) {
		/// Compute @f$ [z] = [2^l + a - b] = [2^l] [a] [b]^{-1} @f$
		Paillier::Ciphertext z = this->encryptedTwoPowL + a - b;

		/// The MSB of @f$ z @f$, @f$ z_l @f$, is the result of the comparison @f$ (z_l = 0 \Rightarrow a < b)) @f$
		/// To extract @f$ z_l @f$, we need to compute @f$ z_l = 2^{-l} (z - (z \pmod {2^l})) @f$

		/// @f$ (z \pmod {2^l}) @f$ needs to be computed interactively

		/// Additively blind @f$ [z] @f$: @f$ [d] = [z + r] = [z] [r] @f$
		const BlindingFactorContainer &blindingFactorContainer = this->blindingFactorCache.Pop();
		Paillier::Ciphertext d = z + blindingFactorContainer.encryptedR;

		/// Re-randomize [d]
		d = this->paillierCryptoProvider.RandomizeCiphertext(d);//is this really needed?

		/// Ask the client to compute @f$ [-(d \pmod {2^l})] @f$
		Paillier::Ciphertext minusDModTwoPowL = this->secureComparisonClient.lock()->ComputeMinusDModTwoPowL(d);

		/// Since @f$ d \equiv z + r \pmod {2^l} \Rightarrow z \pmod {2^l} = ((d \pmod {2^l}) - (r \pmod {2^l})) \pmod {2^l} @f$
		/// Compute @f$ [-\tilde{z}] = [-(d \pmod {2^l}) + (r \pmod {2^l})] = [-(d \pmod {2^l})] [r \pmod {2^l}] @f$
		Paillier::Ciphertext minusTildeZ = minusDModTwoPowL + blindingFactorContainer.encryptedRModTwoPowL;

		/**
		Because @f$ \tilde{z} @f$ is computed @f$ \pmod n @f$ instead of @f$ \pmod {2^l} @f$, in case of underflows, we need to add @f$ 2^l @f$ to get the right results.
		If @f$ d \pmod {2^l} \geq r \pmod 2^l @f$, @f$ z \pmod {2^l} = \tilde{z} @f$
		Else, an underflow occurs, so we need to add @f$ 2^l @f$ to @f$ \tilde{z} @f$
		We need to compare @f$ \hat{d} = d \pmod {2^l} @f$ (held by the client) and @f$ \hat{r} = r \pmod {2^l} @f$ (held by the server) interactively and store the result in @f$ \lambda @f$
		Once the server obtains @f$ [\lambda] @f$, we can compute @f$ [z \pmod {2^l}] = [\tilde{z} + \lambda 2^l] = [\tilde{z}] [\lambda]^{2^l} @f$
		*/

		/// Choose random @f$ s \in {0, 1} @f$
		BigInteger s = RandomProvider::GetInstance().GetRandomInteger(1);
		
		/*
		std::cout << "z: "; this->secureComparisonClient.lock()->DebugPaillierEncryption(z);
		std::cout << "d%2^l: "; this->secureComparisonClient.lock()->DebugPaillierEncryption(this->paillierCryptoProvider.HomomorphicMultiply(minusDModTwoPowL, -1)); 
		std::cout << "r%2^l: "; this->secureComparisonClient.lock()->DebugPaillierEncryption(blindingFactorContainer.encryptedRModTwoPowL);
		std::cout << "s:" << s.ToString(10) << std::endl;
		*/

		/// Compute @f$ \lambda @f$
		Paillier::Ciphertext lambda = this->dgkComparisonServer->ComputeLambda(blindingFactorContainer.hatRBits, s);

		//std::cout << "lambda: "; this->secureComparisonClient.lock()->DebugPaillierEncryption(lambda);

		/// @f$ y = z_l = ([z] [-\hat{d}] [\hat{r}] [\lambda])^{2^{-l} \pmod n} @f$ (because @f$ \lambda \in \{0, -2^l\} @f$ instead of @f$ \{-1, 1\} @f$ - see protocol 4.11)
		Paillier::Ciphertext y = (z + minusDModTwoPowL + blindingFactorContainer.encryptedRModTwoPowL + lambda) * twoPowMinusLModN;

		return y;
	}

	/**
	@param secureComparisonClient a SecureComparisonClient instance
	*/
	void SecureComparisonServer::SetClient (const std::shared_ptr<SecureComparisonClient> &secureComparisonClient) {
		this->secureComparisonClient = secureComparisonClient;
		this->dgkComparisonServer->SetClient(secureComparisonClient->GetDgkComparisonClient());
	}

	/**
	@return The DgkComparisonServer instance.
	*/
	const std::shared_ptr<DgkComparisonServer> &SecureComparisonServer::GetDgkComparisonServer () const {
		return this->dgkComparisonServer;
	}

}//namespace SecureFaceRecognitionUtils
}//namespace SeComLib