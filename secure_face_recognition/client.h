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
@file secure_face_recognition/client.h
@brief Definition of class Client.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef CLIENT_HEADER_GUARD
#define CLIENT_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "core/big_integer.h"
#include "core/paillier.h"
#include "core/dgk.h"

#include "secure_face_recognition_utils/secure_comparison_client.h"

namespace SeComLib {
using namespace Core;
using namespace SecureFaceRecognitionUtils;

namespace SecureFaceRecognition {
	//forward-declare required classes
	class Server;

	/**
	@brief Client
	*/
	class Client {
	public:
		/// The Paillier crypto provider
		Paillier paillierCryptoProvider;

		/// The DGK crypto provider
		Dgk dgkCryptoProvider;

		/// Default constructor
		Client ();

		/// Destructor - void implementation
		~Client () {}

		/// Starts the simulation
		void StartSimulation ();

		/// Sets a reference to the Privacy Service Provider
		void SetServer (const std::shared_ptr<const Server> &server);

		/// Getter for this->secureComparisonClient
		const std::shared_ptr<SecureComparisonClient> &GetSecureComparisonClient () const;

		/// Decrypts and prints a Paillier encrypted integer
		void DebugPaillierEncryption (const Paillier::Ciphertext &input) const;

	private:
		/// A reference to the Server
		std::shared_ptr<const Server> server;

		/// A reference to the SecureComparisonClient
		std::shared_ptr<SecureComparisonClient> secureComparisonClient;

		/// Service Provider configuration path
		static const std::string configurationPath;

		/// Copy constructor - not implemented
		Client (Client const &);

		/// Copy assignment operator - not implemented
		Client operator= (Client const &);
	};
}//namespace SecureFaceRecognition
}//namespace SeComLib

#endif//CLIENT_HEADER_GUARD