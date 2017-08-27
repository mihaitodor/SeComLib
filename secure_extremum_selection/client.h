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
@file secure_extremum_selection/client.h
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
#include "core/secure_extremum_selection_client.h"

//use the desired SecureComparisonClient implementation
#include "private_recommendations_utils/secure_comparison_client.h"
//#include "secure_face_recognition_utils/secure_comparison_client.h"

//include C++ headers
#include <iostream>
#include <vector>
#include <stdexcept>

namespace SeComLib {
using namespace Core;

//specify the namespace of the SecureComparisonClient
using namespace PrivateRecommendationsUtils;
//using namespace SecureFaceRecognitionUtils;

namespace SecureExtremumSelection {
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

		/// Getter for this->secureExtremumSelectionClient
		const std::shared_ptr<SecureExtremumSelectionClient<SecureComparisonServer, SecureComparisonClient>> &GetSecureExtremumSelectionClient () const;

		/// Decrypts and prints a Paillier encrypted integer
		void DebugPaillierEncryption (const Paillier::Ciphertext &input) const;

	private:
		/// A reference to the Server
		std::shared_ptr<const Server> server;

		/// The length of the test vector
		const size_t testVectorLength;

		/// Bitsize of test vector elements
		const size_t l;

		/// The test vector
		std::vector<Paillier::Ciphertext> testVector;

		/// A reference to the SecureExtremumSelectionClient
		std::shared_ptr<SecureExtremumSelectionClient<SecureComparisonServer, SecureComparisonClient>> secureExtremumSelectionClient;

		/// Service Provider configuration path
		static const std::string configurationPath;

		/// Copy constructor - not implemented
		Client (Client const &);

		/// Copy assignment operator - not implemented
		Client operator= (Client const &);
	};
}//namespace SecureExtremumSelection
}//namespace SeComLib

#endif//CLIENT_HEADER_GUARD