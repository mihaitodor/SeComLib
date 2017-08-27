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
@file secure_extremum_selection/server.cpp
@brief Implementation of class Server.
@details Dummy server.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "server.h"
//avoid circular includes
#include "client.h"

namespace SeComLib {
namespace SecureExtremumSelection {
	/**
	Set the configuration path.
	*/
	const std::string Server::configurationPath("SecureExtremumSelection");

	/**
	@param paillierPublicKey The Paillier public key
	@param dgkPublicKey The DGK public key
	*/
	Server::Server (const PaillierPublicKey &paillierPublicKey, const DgkPublicKey &dgkPublicKey) :
		paillierCryptoProvider(paillierPublicKey),
		dgkCryptoProvider(dgkPublicKey),
		secureExtremumSelectionServer(std::make_shared<SecureExtremumSelectionServer<SecureComparisonServer, SecureComparisonClient>>(paillierCryptoProvider, dgkCryptoProvider, configurationPath)) {
	}

	/**
	@param items encrypted input vector
	@return the encrypted minimum
	*/
	Paillier::Ciphertext Server::ComputeMinimum (std::vector<Paillier::Ciphertext> &items) const {
		return this->secureExtremumSelectionServer->GetMinimum(items);
	}

	/**
	@param items encrypted input vector
	@return the encrypted maximum
	*/
	Paillier::Ciphertext Server::ComputeMaximum (std::vector<Paillier::Ciphertext> &items) const {
		return this->secureExtremumSelectionServer->GetMaximum(items);
	}

	/**
	@param client a Client instance
	*/
	void Server::SetClient (const std::shared_ptr<const Client> &client) {
		this->client = client;
		this->secureExtremumSelectionServer->SetClient(client->GetSecureExtremumSelectionClient());
	}

	/**
	@return The SecureExtremumSelectionServer instance.
	*/
	const std::shared_ptr<SecureExtremumSelectionServer<SecureComparisonServer, SecureComparisonClient>> &Server::GetSecureExtremumSelectionServer () const {
		return this->secureExtremumSelectionServer;
	}

}//namespace SecureExtremumSelection
}//namespace SeComLib