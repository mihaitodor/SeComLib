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
@file secure_extremum_selection/client.cpp
@brief Implementation of class Client.
@details Dummy client.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "client.h"
//avoid circular includes
#include "server.h"

namespace SeComLib {
namespace SecureExtremumSelection {
	/**
	Set the configuration path.
	*/
	const std::string Client::configurationPath("SecureExtremumSelection");

	/**
	Generates the Paillier and DGK keys.
	*/
	Client::Client () :
		testVectorLength(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".testVectorLength")),
		l(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".l")) {
		this->paillierCryptoProvider.GenerateKeys();

		this->dgkCryptoProvider.GenerateKeys();

		//can't initialize it in the initialization list, because the crypto providers need to generate keys first
		this->secureExtremumSelectionClient = std::make_shared<SecureExtremumSelectionClient<SecureComparisonServer, SecureComparisonClient>>(this->paillierCryptoProvider, this->dgkCryptoProvider, this->configurationPath);
	}

	/**
	Generates a random test vector and computes the minimum and the maximum
	*/
	void Client::StartSimulation () {
		/// Populate the test vector with random encrypted values
		this->testVector.reserve(this->testVectorLength);
		for (size_t i = 0; i < this->testVectorLength; ++i) {
			this->testVector.emplace_back(this->paillierCryptoProvider.EncryptInteger(RandomProvider::GetInstance().GetRandomInteger(this->l)));
		}

		//debugging
		std::cout << "Test vector:" << std::endl;
		for (size_t i = 0; i < this->testVectorLength; ++i) {
			this->DebugPaillierEncryption(this->testVector[i]);
		}

		/// Compute extrema
		Paillier::Ciphertext minimum = this->server->ComputeMinimum(this->testVector);
		Paillier::Ciphertext maximum = this->server->ComputeMaximum(this->testVector);

		//debugging
		std::cout << "Minimum: "; this->DebugPaillierEncryption(minimum);
		std::cout << "Maximum: "; this->DebugPaillierEncryption(maximum);
	}

	/**
	@param server a Server instance
	*/
	void Client::SetServer (const std::shared_ptr<const Server> &server) {
		this->server = server;
		this->secureExtremumSelectionClient->SetServer(server->GetSecureExtremumSelectionServer());
	}

	/**
	@return The SecureExtremumSelectionClient instance.
	*/
	const std::shared_ptr<SecureExtremumSelectionClient<SecureComparisonServer, SecureComparisonClient>> &Client::GetSecureExtremumSelectionClient () const {
		return this->secureExtremumSelectionClient;
	}

	/**
	@param input a Paillier encrypted integer
	*/
	void Client::DebugPaillierEncryption (const Paillier::Ciphertext &input) const {
		std::cout << this->paillierCryptoProvider.DecryptInteger(input).ToString(10) << std::endl;
	}

}//namespace SecureExtremumSelection
}//namespace SeComLib