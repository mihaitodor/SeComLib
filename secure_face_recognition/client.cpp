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
@file secure_face_recognition/client.cpp
@brief Implementation of class Client.
@details Dummy client.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "client.h"
//avoid circular includes
#include "server.h"

namespace SeComLib {
namespace SecureFaceRecognition {
	/**
	Set the configuration path.
	*/
	const std::string Client::configurationPath("SecureFaceRecognition");

	/**
	Generates the Paillier and DGK keys.
	*/
	Client::Client () {
		this->paillierCryptoProvider.GenerateKeys();

		this->dgkCryptoProvider.GenerateKeys();

		//can't initialize it in the initialization list, because the crypto providers need to generate keys first
		this->secureComparisonClient = std::make_shared<SecureComparisonClient>(this->paillierCryptoProvider, this->dgkCryptoProvider, this->configurationPath);
	}

	/**
	Prints @f$ a < b ? 0 : 1 @f$
	*/
	void Client::StartSimulation () {
		BigInteger a = Utils::Config::GetInstance().GetParameter<long>(this->configurationPath + ".a");
		BigInteger b = Utils::Config::GetInstance().GetParameter<long>(this->configurationPath + ".b");

		Paillier::Ciphertext comparison = this->server->SecureComparison(this->paillierCryptoProvider.EncryptInteger(a), this->paillierCryptoProvider.EncryptInteger(b));

		/// Print the comparison result
		this->DebugPaillierEncryption(comparison);
	}

	/**
	@param server a Server instance
	*/
	void Client::SetServer (const std::shared_ptr<const Server> &server) {
		this->server = server;
		this->secureComparisonClient->SetServer(server->GetSecureComparisonServer());
	}

	/**
	@return The SecureComparisonClient instance.
	*/
	const std::shared_ptr<SecureComparisonClient> &Client::GetSecureComparisonClient () const {
		return this->secureComparisonClient;
	}

	/**
	@param input a Paillier encrypted integer
	*/
	void Client::DebugPaillierEncryption (const Paillier::Ciphertext &input) const {
		std::cout << this->paillierCryptoProvider.DecryptInteger(input).ToString(10) << std::endl;
	}

}//namespace SecureFaceRecognition
}//namespace SeComLib