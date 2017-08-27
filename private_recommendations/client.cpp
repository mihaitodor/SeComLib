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
@file private_recommendations/client.cpp
@brief Implementation of class Client.
@details A test client that wants to receive recommendations
@author Mihai Todor (todormihai@gmail.com)
*/

#include "client.h"

namespace SeComLib {
namespace PrivateRecommendations {
	/**
	Set the configuration path.
	*/
	const std::string Client::configurationPath("PrivateRecommendations");

	/**
	Assumes that the client has a secure channel to the PrivacyServiceProvider.

	@param serviceProvider a ServiceProvider instance
	@param privacyServiceProvider a PrivacyServiceProvider instance
	@param publicKey the Paillier public key of the PrivacyServiceProvider
	*/
	Client::Client (const std::shared_ptr<ServiceProvider> &serviceProvider, const std::shared_ptr<PrivacyServiceProvider> &privacyServiceProvider, const PaillierPublicKey &publicKey) :
		serviceProvider(serviceProvider),
		privacyServiceProvider(privacyServiceProvider),
		paillierCryptoProvider(publicKey),
		blindingFactorCache(paillierCryptoProvider, BlindingFactorCacheParameters(configurationPath + ".BlindingFactorCache", Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".l"))),
		userCount(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".userCount")) {
	}

	/**
	Fetches encrypted values from the Service Provider, blinds them and sends them to the Privacy Service Provider for decryption.
	*/
	void Client::ComputeRecommendations () {
	#ifdef FIRST_USER_ONLY
		for (size_t user = 0; user < 1; ++user) {
	#else
		for (size_t user = 0; user < this->userCount; ++user) {
	#endif
			//measure the time it takes to decrypt the recommendations for each user
			Utils::CpuTimer recommendationsProcessingTimer;

			/*
			std::cout << "User " << user << ":" << std::endl << std::endl;
			*/

			/// Fetch @f$ [L] @f$ and @f$ [UR_{sum}] @f$ from the Service Provider
			Paillier::Ciphertext encryptedL = this->serviceProvider->GetEncryptedL(user);
			ServiceProvider::EncryptedUserData encryptedURSum = this->serviceProvider->GetEncryptedURSum(user);

			const BlindingFactorContainer &LblindingFactor = this->blindingFactorCache.Pop();

			/// @f$ L = Dec([L][r]) - r @f$
			unsigned long L = (this->privacyServiceProvider->SecureDecryption(encryptedL + LblindingFactor.encryptedR) - LblindingFactor.r).ToUnsignedLong();

			/*
			std::cout << "L:" << L << std::endl;
			*/
			if (L == 0) {
				std::cout << "No similar users found." << std::endl;
				continue;
			}

			std::vector<unsigned long> URSum;
			for (ServiceProvider::EncryptedUserData::iterator encryptedURSumIterator = encryptedURSum.begin(); encryptedURSumIterator != encryptedURSum.end(); ++encryptedURSumIterator) {
				const BlindingFactorContainer &URSumblindingFactor = this->blindingFactorCache.Pop();

				/// @f$ UR_{sum}^i = Dec([UR_{sum}^i][r]) - r @f$
				URSum.push_back((this->privacyServiceProvider->SecureDecryption(*encryptedURSumIterator + URSumblindingFactor.encryptedR) - URSumblindingFactor.r).ToUnsignedLong());
			}

			/*
			std::cout << "UR_sum:" << std::endl;
			for (std::vector<unsigned long>::const_iterator URSumIterator = URSum.begin(); URSumIterator != URSum.end(); ++URSumIterator) {
				std::cout << *URSumIterator << std::endl;
			}

			std::cout << "Recommendations:" << std::endl;
			for (std::vector<unsigned long>::const_iterator URSumIterator = URSum.begin(); URSumIterator != URSum.end(); ++URSumIterator) {
				std::cout << static_cast<double>(*URSumIterator) / static_cast<double>(L) << std::endl;
			}
			*/

			std::cout << std::endl;

			std::cout << "Processed recommendations for user " << user << " in " << recommendationsProcessingTimer.ToString() << std::endl;
		}
	}

}//namespace PrivateRecommendations
}//namespace SeComLib