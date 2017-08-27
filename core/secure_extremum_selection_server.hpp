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
@file core/secure_extremum_selection_server.hpp
@brief Implementation of template members from class SecureExtremumSelectionServer. To be included in secure_extremum_selection_server.h
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_EXTREMUM_SELECTION_SERVER_IMPLEMENTATION_GUARD
#define SECURE_EXTREMUM_SELECTION_SERVER_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/**
	@param paillierCryptoProvider The Paillier crypto provider
	@param dgkCryptoProvider The DGK crypto provider
	@param configurationPath the configuration path for parameters
	*/
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	SecureExtremumSelectionServer<T_SecureComparisonServer, T_SecureComparisonClient>::SecureExtremumSelectionServer (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const std::string &configurationPath) :
		paillierCryptoProvider(paillierCryptoProvider),
		dgkCryptoProvider(dgkCryptoProvider),
		secureComparisonServer(std::make_shared<T_SecureComparisonServer>(paillierCryptoProvider, dgkCryptoProvider, configurationPath)),
		secureMultiplicationServer(std::make_shared<SecureMultiplicationServer<Paillier>>(paillierCryptoProvider, Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".l"), configurationPath)) {
	}

	/**
	@param items encrypted input vector
	@return The encrypted minimum
	*/
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	Paillier::Ciphertext SecureExtremumSelectionServer<T_SecureComparisonServer, T_SecureComparisonClient>::GetMinimum (const ItemContainer &items) const {
		if (items.size() < 2) {
			return *items.begin();
		}

		/* Create a vector of the minimums obtained by comparing each adjacent pair of items:
		@f$ [min] = \left\{\begin{array}{ll} [0 * (y - x) + x] = ([0] * [y - x])[x] = [x] & \text{if $ x < y $} \\ [1 * (y - x) + x] = ([1] * [y - x])[x] = [y] & \text{if $ x \geq y} \end{array} \right. @f$
		*/
		ItemContainer temp;
		temp.reserve(items.size() / 2 + items.size() % 2);//inefficient ceil
		for (size_t i = 0; i < items.size() - 1; i += 2) {
			temp.push_back(this->secureMultiplicationServer->Multiply(this->secureComparisonServer->Compare(items[i], items[i + 1]), items[i + 1] - items[i]) + items[i]);
		}

		//for odd lenghts, we also want to keep the last element
		if (items.size() % 2 == 1) {
			temp.push_back(*items.rbegin());
		}

		/// Recursively compute the minimum
		return this->GetMinimum(temp);
	}

	/**
	@param items encrypted input vector
	@return The encrypted maximum
	*/
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	Paillier::Ciphertext SecureExtremumSelectionServer<T_SecureComparisonServer, T_SecureComparisonClient>::GetMaximum (const ItemContainer &items) const {
		if (items.size() < 2) {
			return *items.begin();
		}

		/* Create a vector of the maximums obtained by comparing each adjacent pair of items:
		@f$ [max] = \left\{\begin{array}{ll} [0 * (x - y) + y] = ([0] * [x - y])[y] = [y] & \text{if $ x < y $} \\ [1 * (x - y) + y] = ([1] * [x - y])[y] = [x] & \text{if $ x \geq y} \end{array} \right. @f$
		*/
		ItemContainer temp;
		temp.reserve(items.size() / 2 + items.size() % 2);//inefficient ceil
		for (size_t i = 0; i < items.size() - 1; i += 2) {
			temp.push_back(this->secureMultiplicationServer->Multiply(this->secureComparisonServer->Compare(items[i], items[i + 1]), items[i] - items[i + 1]) + items[i + 1]);
		}

		//for odd lenghts, we also want to keep the last element
		if (items.size() % 2 == 1) {
			temp.push_back(*items.rbegin());
		}

		/// Recursively compute the maximum
		return this->GetMaximum(temp);
	}

	/**
	@param secureExtremumSelectionClient a SecureExtremumSelectionClient instance
	*/
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	void SecureExtremumSelectionServer<T_SecureComparisonServer, T_SecureComparisonClient>::SetClient (const std::shared_ptr<SecureExtremumSelectionClient<T_SecureComparisonServer, T_SecureComparisonClient>> &secureExtremumSelectionClient) {
		this->secureExtremumSelectionClient = secureExtremumSelectionClient;
		this->secureComparisonServer->SetClient(secureExtremumSelectionClient->GetSecureComparisonClient());
		this->secureMultiplicationServer->SetClient(secureExtremumSelectionClient->GetSecureMultiplicationClient());
	}

	/**
	@return The T_SecureComparisonServer instance.
	*/
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	const std::shared_ptr<T_SecureComparisonServer> &SecureExtremumSelectionServer<T_SecureComparisonServer, T_SecureComparisonClient>::GetSecureComparisonServer () const {
		return this->secureComparisonServer;
	}

	/**
	@return The SecureMultiplicationServer instance.
	*/
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	const std::shared_ptr<SecureMultiplicationServer<Paillier>> &SecureExtremumSelectionServer<T_SecureComparisonServer, T_SecureComparisonClient>::GetSecureMultiplicationServer () const {
		return this->secureMultiplicationServer;
	}

}//namespace Core
}//namespace SeComLib

#endif//SECURE_EXTREMUM_SELECTION_SERVER_IMPLEMENTATION_GUARD