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
@file core/secure_extremum_selection_client.hpp
@brief Implementation of template members from class SecureExtremumSelectionClient. To be included in secure_extremum_selection_client.h
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_EXTREMUM_SELECTION_CLIENT_IMPLEMENTATION_GUARD
#define SECURE_EXTREMUM_SELECTION_CLIENT_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/**
	@param paillierCryptoProvider The Paillier crypto provider
	@param dgkCryptoProvider The DGK crypto provider
	@param configurationPath the configuration path for parameters
	*/
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	SecureExtremumSelectionClient<T_SecureComparisonServer, T_SecureComparisonClient>::SecureExtremumSelectionClient (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const std::string &configurationPath) :
		paillierCryptoProvider(paillierCryptoProvider),
		dgkCryptoProvider(dgkCryptoProvider),
		secureComparisonClient(std::make_shared<T_SecureComparisonClient>(paillierCryptoProvider, dgkCryptoProvider, configurationPath)),
		secureMultiplicationClient(std::make_shared<SecureMultiplicationClient<Paillier>>(paillierCryptoProvider)) {
	}

	/**
	@param secureExtremumSelectionServer a SecureExtremumSelectionServer instance
	*/
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	void SecureExtremumSelectionClient<T_SecureComparisonServer, T_SecureComparisonClient>::SetServer (const std::shared_ptr<SecureExtremumSelectionServer<T_SecureComparisonServer, T_SecureComparisonClient>> &secureExtremumSelectionServer) {
		this->secureExtremumSelectionServer = secureExtremumSelectionServer;
		this->secureComparisonClient->SetServer(secureExtremumSelectionServer->GetSecureComparisonServer());
		this->secureMultiplicationClient->SetServer(secureExtremumSelectionServer->GetSecureMultiplicationServer());
	}

	/**
	@return The T_SecureComparisonClient instance.
	*/
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	const std::shared_ptr<T_SecureComparisonClient> &SecureExtremumSelectionClient<T_SecureComparisonServer, T_SecureComparisonClient>::GetSecureComparisonClient () const {
		return this->secureComparisonClient;
	}

	/**
	@return The SecureMultiplicationClient instance.
	*/
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	const std::shared_ptr<SecureMultiplicationClient<Paillier>> &SecureExtremumSelectionClient<T_SecureComparisonServer, T_SecureComparisonClient>::GetSecureMultiplicationClient () const {
		return this->secureMultiplicationClient;
	}

}//namespace Core
}//namespace SeComLib

#endif//SECURE_EXTREMUM_SELECTION_CLIENT_IMPLEMENTATION_GUARD