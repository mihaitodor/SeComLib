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
@file private_recommendations/privacy_service_provider.cpp
@brief Implementation of class PrivacyServiceProvider.
@details The Service Provider (SP) has a business interest in generating recommendations for his customers. He has resources for storage and processing.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "privacy_service_provider.h"
//avoid circular includes
#include "service_provider.h"

namespace SeComLib {
namespace PrivateRecommendations {
	/**
	Set the configuration path.
	*/
	const std::string PrivacyServiceProvider::configurationPath("PrivateRecommendations");

	/**
	Generates the Paillier and DGK keys.
	*/
	PrivacyServiceProvider::PrivacyServiceProvider () {
		this->paillierCryptoProvider.GenerateKeys();

		this->dgkCryptoProvider.GenerateKeys();

		//can't initialize it in the initialization list, because the crypto providers need to generate keys first
		this->secureComparisonClient = std::make_shared<SecureComparisonClient>(this->paillierCryptoProvider, this->dgkCryptoProvider, this->configurationPath);
		this->secureMultiplicationClient = std::make_shared<SecureMultiplicationClient<Paillier>>(this->paillierCryptoProvider);
	}

	/**
	@param input Paillier ciphertext
	@return the decrypted integer
	*/
	BigInteger PrivacyServiceProvider::SecureDecryption (const Paillier::Ciphertext &input) const {
		return this->paillierCryptoProvider.DecryptInteger(input);
	}

	/**
	@param serviceProvider a ServiceProvider instance
	*/
	void PrivacyServiceProvider::SetServiceProvider (const std::shared_ptr<const ServiceProvider> &serviceProvider) {
		this->serviceProvider = serviceProvider;
		this->secureComparisonClient->SetServer(serviceProvider->GetSecureComparisonServer());
		this->secureMultiplicationClient->SetServer(serviceProvider->GetSecureMultiplicationServer());
	}

	/**
	@return The SecureComparisonClient instance.
	*/
	const std::shared_ptr<SecureComparisonClient> &PrivacyServiceProvider::GetSecureComparisonClient () const {
		return this->secureComparisonClient;
	}

	/**
	@return The SecureMultiplicationClient instance.
	*/
	const std::shared_ptr<SecureMultiplicationClient<Paillier>> &PrivacyServiceProvider::GetSecureMultiplicationClient () const {
		return this->secureMultiplicationClient;
	}

	/**
	@return a const reference to the Paillier public key
	*/
	const PaillierPublicKey &PrivacyServiceProvider::GetPaillierPublicKey () const {
		return this->paillierCryptoProvider.GetPublicKey();
	}

	/**
	@return a const reference to the DGK public key
	*/
	const DgkPublicKey &PrivacyServiceProvider::GetDgkPublicKey () const {
		return this->dgkCryptoProvider.GetPublicKey();
	}

	/**
	@param input a Paillier encrypted integer
	*/
	void PrivacyServiceProvider::DebugPaillierEncryption (const Paillier::Ciphertext &input) const {
		std::cout << this->paillierCryptoProvider.DecryptInteger(input).ToString(10) << std::endl;
	}

}//namespace PrivateRecommendations
}//namespace SeComLib