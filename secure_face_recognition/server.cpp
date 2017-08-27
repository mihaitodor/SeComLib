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
@file secure_face_recognition/server.cpp
@brief Implementation of class Server.
@details Dummy server.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "server.h"
//avoid circular includes
#include "client.h"

namespace SeComLib {
namespace SecureFaceRecognition {
	/**
	Set the configuration path.
	*/
	const std::string Server::configurationPath("SecureFaceRecognition");

	/**
	@param paillierPublicKey The Paillier public key
	@param dgkPublicKey The DGK public key
	*/
	Server::Server (const PaillierPublicKey &paillierPublicKey, const DgkPublicKey &dgkPublicKey) :
		paillierCryptoProvider(paillierPublicKey),
		dgkCryptoProvider(dgkPublicKey),
		secureComparisonServer(std::make_shared<SecureComparisonServer>(paillierCryptoProvider, dgkCryptoProvider, configurationPath)) {
	}

	/**
	@param a Paillier encryption
	@param b Paillier encryption
	@return @f$ a < b ? [0] : [1] @f$
	*/
	Paillier::Ciphertext Server::SecureComparison (const Paillier::Ciphertext &a, const Paillier::Ciphertext &b) const {
		/**
		To determine the minimum value, the server can compute @f$ [min] = [a + z_l (b - a)] = [a] ([y] \times ([b] [a]^{-1})) @f$ using an interactive protocol for the secure multiplication.
		Since this operation is rather expensive and the client already has the value @f$ d = 2^l + a - b + r @f$, the server can blind @f$ [y] @f$ with @f$ \eta \in_R \{0, 1\} @f$: 
		if @f$ \eta = 1 \Rightarrow [\tilde{y}] = [1] [y]^{-1} @f$ else @f$ [\tilde{y}] = [y] @f$
		and send it to the client. The client can decrypt @f$ [\tilde{y}] @f$ and compute @f$ [y d] @f$, which gets sent back to the server.
		The server now computes @f$ [\tilde{min}] = [b + y d - (r + 2^l) y] = [b] [yd] [y]^{-(r + 2^l)} @f$.
		If @f$ \eta = 1 \Rightarrow [min] = [\tilde{min}] @f$ else @f$ [min] = [a + b - \tilde{min}] = [a] [b] [\tilde{min}]^{-1} @f$
		*/

		return this->secureComparisonServer->Compare(a, b);
	}

	/**
	@param client a Client instance
	*/
	void Server::SetClient (const std::shared_ptr<const Client> &client) {
		this->client = client;
		this->secureComparisonServer->SetClient(client->GetSecureComparisonClient());
	}

	/**
	@return The SecureComparisonServer instance.
	*/
	const std::shared_ptr<SecureComparisonServer> &Server::GetSecureComparisonServer () const {
		return this->secureComparisonServer;
	}

}//namespace SecureFaceRecognition
}//namespace SeComLib