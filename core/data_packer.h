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
@file core/data_packer.h
@brief Definition of template class DataPacker.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef DATA_PACKER_HEADER_GUARD
#define DATA_PACKER_HEADER_GUARD

#include "utils/config.h"

//include C++ headers
#include <deque>
#include <stdexcept>

namespace SeComLib {
namespace Core {
	/**
	@brief Template class which implements the data packing functionality.

	@tparam T_CryptoProvider The type of the crypto provider, which must be derived from template class CryptoProvider
	*/
	template <typename T_CryptoProvider>
	class DataPacker {
	public:

		/**
		@brief Container for data buckets
		*/
		struct DataBucket {
		public:
			/// The front padding (@f$ \geq 0 @f$)
			BigInteger frontPadding;

			/// The data (@f$ \geq 0 @f$)
			BigInteger data;

			/// The back padding (@f$ \geq 0 @f$)
			BigInteger backPadding;
		};

		/// Define a vector template specialization for vectors of unpacked data
		typedef std::deque<typename DataPacker<T_CryptoProvider>::DataBucket> UnpackedData;

		/// Define a vector template specialization for vectors of packed data
		typedef std::deque<typename T_CryptoProvider::Ciphertext> PackedData;

		/// Constructor with custom data sizes
		DataPacker (const T_CryptoProvider &cryptoProvider, const size_t dataSize, const size_t frontPaddingSize = 0, const size_t backPaddingSize = 0);

		/// Destructor
		~DataPacker () {}

		/// Pack data
		PackedData Pack (const UnpackedData &input) const;

		/// Unpack data
		UnpackedData Unpack (const PackedData &input, const size_t totalBucketCount) const;

		/// Add two vectors of packed data
		PackedData HomomorphicAdd (const PackedData &lhs, const PackedData &rhs);

		/// Multiply a vector of packed data with a constant plaintext term
		PackedData HomomorphicMultiply (const PackedData &lhs, const BigInteger &rhs);

	private:
		/// Reference to the Crypto Provider
		const T_CryptoProvider &cryptoProvider;

		/// The size (in bits) of the front padding (defaults to 0)
		size_t frontPaddingSize;

		/// The maximum value that can be stored in DataBucket.frontPadding
		BigInteger frontPaddingMessageSpace;
		
		/// The size (in bits) of the data
		size_t dataSize;

		/// The maximum value that can be stored in DataBucket.data
		BigInteger dataMessageSpace;

		/// The size (in bits) of the back padding (defaults to 0)
		size_t backPaddingSize;

		/// The maximum value that can be stored in DataBucket.backPadding
		BigInteger backPaddingMessageSpace;

		/// The size (in bits) of each bucket (computed in the constructor)
		size_t bucketSize;

		/// The maximum number of buckets that can pe packet in a single encryption
		size_t bucketsPerEncryption;

		/// Initialize class members
		void initialize ();

		/// Copy constructor - not implemented
		DataPacker (DataPacker const &);

		/// Copy assignment operator - not implemented
		DataPacker operator= (DataPacker const &);
	};
}//namespace Core
}//namespace SeComLib

//Separate the implementation from the declaration of template methods
#include "data_packer.hpp"

#endif//DATA_PACKER_HEADER_GUARD