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
@file private_recommendations_utils/secure_comparison_server.cpp
@brief Implementation of class SecureComparisonServer.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "secure_comparison_server.h"
//avoid circular includes
#include "secure_comparison_client.h"

namespace SeComLib {
namespace PrivateRecommendationsUtils {

	/**
	Computes @f$ [2^l] @f$

	@note VS2010 does not support constructor chaining...

	@param paillierCryptoProvider the Paillier crypto provider
	@param dgkCryptoProvider the DGK crypto provider
	@param configurationPath the configuration path for parameters
	*/
	SecureComparisonServer::SecureComparisonServer (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const std::string &configurationPath) :
		paillierCryptoProvider(paillierCryptoProvider),
		dgkCryptoProvider(dgkCryptoProvider),
		l(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".l")),
		minusThreshold(paillierCryptoProvider.GetEncryptedZero(false)),//set this member to [0], since we won't be using it in this case
		twoPowL(BigInteger(2).GetPow(static_cast<unsigned long>(l))),
		encryptedTwoPowL(paillierCryptoProvider.EncryptInteger(twoPowL)),
		blindingFactorCache(paillierCryptoProvider, ComparisonBlindingFactorCacheParameters(configurationPath + ".BlindingFactorCache", l)),
		dgkComparisonServer(std::make_shared<DgkComparisonServer>(paillierCryptoProvider, dgkCryptoProvider, l)) {
	}

	/**
	Computes @f$ [-\delta] @f$ and @f$ [2^l] @f$

	@param paillierCryptoProvider the Paillier crypto provider
	@param dgkCryptoProvider the DGK crypto provider
	@param similarityTreshold he threshold to which similarity values will be compared
	@param configurationPath the configuration path for parameters
	*/
	SecureComparisonServer::SecureComparisonServer (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const BigInteger &similarityTreshold, const std::string &configurationPath) :
		paillierCryptoProvider(paillierCryptoProvider),
		dgkCryptoProvider(dgkCryptoProvider),
		l(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".l")),
		minusThreshold(paillierCryptoProvider.EncryptInteger(-similarityTreshold)),
		twoPowL(BigInteger(2).GetPow(static_cast<unsigned long>(l))),
		encryptedTwoPowL(paillierCryptoProvider.EncryptInteger(twoPowL)),
		blindingFactorCache(paillierCryptoProvider, ComparisonBlindingFactorCacheParameters(configurationPath + ".BlindingFactorCache", l)),
		dgkComparisonServer(std::make_shared<DgkComparisonServer>(paillierCryptoProvider, dgkCryptoProvider, l)) {
	}

	/**
	@param a encrypted left hand side operand
	@param b encrypted right hand side operand
	@return @f$ a \leq b ? [1] : [0] @f$
	*/
	Paillier::Ciphertext SecureComparisonServer::Compare (const Paillier::Ciphertext &a, const Paillier::Ciphertext &b) {
		return this->compare(a, -b);
	}

	/**
	Compares @f$ [sim_{(A, B)}] @f$ with @f$ \delta @f$. If @f$ [sim_{(A, B)}] \geq \delta @f$ the result is 1. Otherwise it is 0.

	@note In the paper, it is stated that 0 is returned in the case of equality. As discussed with Thijs Veugen, this is a mistake.

	@param similarityValue the encrypted similarity value
	@return encrypted result of the comparison: @f$ [0] @f$ or @f$ [1] @f$
	*/
	Paillier::Ciphertext SecureComparisonServer::Compare (const Paillier::Ciphertext &similarityValue) {
		return this->compare(similarityValue, this->minusThreshold);
	}

	/**
	Compares @f$ [a] @f$ with @f$ [b] @f$. If @f$ [a] \geq [b] @f$ the result is 1. Otherwise it is 0.

	@param a @f$ [a] @f$
	@param minusB @f$ [-b] @f$
	@return encrypted result of the comparison: @f$ [0] @f$ or @f$ [1] @f$
	*/
	Paillier::Ciphertext SecureComparisonServer::compare (const Paillier::Ciphertext &a, const Paillier::Ciphertext &minusB) {
		/// @f$ [d] = [2^l] [sim_{(A, B)}] [\delta]^{-1} @f$
		Paillier::Ciphertext d = encryptedTwoPowL + a + minusB;

		const BlindingFactorContainer &blindingFactorContainer = this->blindingFactorCache.Pop();

		/// @f$ [z] = [d] [r] @f$
		Paillier::Ciphertext z = d + blindingFactorContainer.encryptedR;

		/// Compute @f$ [z \div 2^l] @f$ by interacting with the client
		Paillier::Ciphertext zDivTwoPowL = this->secureComparisonClient.lock()->ComputeZDivTwoPowL(z);

		/// If @f$ r \pmod 2^l > z \pmod 2^l @f$ then @f$ t = [1] @f$, else @f$ t = [0] @f$
		Paillier::Ciphertext t = this->dgkComparisonServer->Compare(blindingFactorContainer.rModTwoPowL);

		/// @f$ [\gamma(A, i)] = [z \div 2^l] ([r \div 2^l] [t])^{-1} @f$
		Paillier::Ciphertext gamma = zDivTwoPowL - (blindingFactorContainer.encryptedRDivTwoPowL + t);

		/*
		std::cout << "sim(A,B): "; this->secureComparisonClient.lock()->DebugPaillierEncryption(similarityValue);
		std::cout << "-delta: "; this->secureComparisonClient.lock()->DebugPaillierEncryption(minusThreshold);
		std::cout << "2^l: "; this->secureComparisonClient.lock()->DebugPaillierEncryption(encryptedTwoPowL);
		std::cout << "d: "; this->secureComparisonClient.lock()->DebugPaillierEncryption(d);
		std::cout << "z: "; this->secureComparisonClient.lock()->DebugPaillierEncryption(z);
		std::cout << "z div 2^l: "; this->secureComparisonClient.lock()->DebugPaillierEncryption(zDivTwoPowL);
		std::cout << "r (mod 2^l): " << blindingFactorContainer.rModTwoPowL.ToString(10) << std::endl;
		std::cout << "r div 2^l: "; this->secureComparisonClient.lock()->DebugPaillierEncryption(blindingFactorContainer.encryptedRDivTwoPowL);
		std::cout << "t: "; this->secureComparisonClient.lock()->DebugPaillierEncryption(t);
		std::cout << "gamma: "; this->secureComparisonClient.lock()->DebugPaillierEncryption(gamma);
		*/

		return gamma;
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

}//namespace PrivateRecommendationsUtils
}//namespace SeComLib