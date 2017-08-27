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
@file core/data_packer.hpp
@brief Implementation of template class DataPacker. To be included in data_packer.h
@details DataPacker is a template class that performs data packing and encryption using a CryptoProvider. It can handle only pozitive numbers at this time.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef DATA_PACKER_IMPLEMENTATION_GUARD
#define DATA_PACKER_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/**
	Initializes the DataPacker parameters with custom values

	@param cryptoProvider the crypto provider
	@param dataSize the size (in bits) of the data
	@param frontPaddingSize the size (in bits) of the front padding (defaults to 0)
	@param backPaddingSize the size (in bits) of the back padding (defaults to 0)
	*/
	template <typename T_CryptoProvider>
	DataPacker<T_CryptoProvider>::DataPacker (const T_CryptoProvider &cryptoProvider, const size_t dataSize, const size_t frontPaddingSize, const size_t backPaddingSize) :
		cryptoProvider(cryptoProvider),
		frontPaddingSize(frontPaddingSize),
		dataSize(dataSize),
		backPaddingSize(backPaddingSize) {
		this->initialize();
	}
	
	/**
	Packs the unencrypted bucket vector into a vector of encrypted data

	@param input a vector of unencrypted data buckets
	@return A vector of encrypted and packed data buckets.
	*/
	template <typename T_CryptoProvider>
	typename DataPacker<T_CryptoProvider>::PackedData DataPacker<T_CryptoProvider>::Pack (const typename DataPacker<T_CryptoProvider>::UnpackedData &input) const {
		typename DataPacker<T_CryptoProvider>::PackedData output;

		//initialize the packed buckets
		BigInteger packedBuckets(0);
		//initialize the bucket counter
		size_t packedBucketCounter = 0;
		for (typename DataPacker<T_CryptoProvider>::UnpackedData::const_iterator bucketIterator = input.begin(); bucketIterator != input.end(); ++bucketIterator) {
			//test if we packed enough buckets to fill the entire span of the message space
			if (packedBucketCounter == this->bucketsPerEncryption) {
				output.emplace_back(this->cryptoProvider.EncryptInteger(packedBuckets));

				//create the next packed bucket
				packedBuckets = BigInteger(0);
				packedBucketCounter = 0;
			}

			/// We expect only positive values in the DataBucket container

			//pack front padding element
			if (this->frontPaddingSize > 0) {
				packedBuckets += (*bucketIterator).frontPadding << (static_cast<unsigned long>(packedBucketCounter * this->bucketSize));
			}

			//pack data element
			packedBuckets += (*bucketIterator).data << (static_cast<unsigned long>(packedBucketCounter * this->bucketSize + this->frontPaddingSize));

			//pack back padding element
			if (this->backPaddingSize > 0) {
				packedBuckets += (*bucketIterator).backPadding << (static_cast<unsigned long>(packedBucketCounter * this->bucketSize + this->frontPaddingSize + this->dataSize));
			}

			++packedBucketCounter;
		}

		//don't forget to store the last set of packed buckets (it might not contain as many as this->bucketsPerEncryption buckets, so we need to know how many buckets to unpack)
		output.emplace_back(this->cryptoProvider.EncryptInteger(packedBuckets));

		return output;
	}

	/**
	Unpacks the encrypted packed data into a vector of data buckets

	@param input a vector of encrypted packed data
	@param totalBucketCount the number of buckets to unpack
	@return A vector of unencrypted data buckets.
	*/
	template <typename T_CryptoProvider>
	typename DataPacker<T_CryptoProvider>::UnpackedData DataPacker<T_CryptoProvider>::Unpack (const typename DataPacker<T_CryptoProvider>::PackedData &input, const size_t totalBucketCount) const {
		typename DataPacker<T_CryptoProvider>::UnpackedData output;

		for (typename DataPacker<T_CryptoProvider>::PackedData::const_iterator packedDataIterator = input.begin(); packedDataIterator != input.end(); ++packedDataIterator) {
			//decrypt the packed buckets
			BigInteger packedBuckets = this->cryptoProvider.DecryptInteger(*packedDataIterator);

			//extract each data bucket
			for (size_t i = 0; i < this->bucketsPerEncryption; ++i) {
				DataBucket bucket;

				if (this->frontPaddingSize > 0) {
					//extract front padding element
					bucket.frontPadding = packedBuckets % this->frontPaddingMessageSpace;

					//shift bits to extract the data element
					packedBuckets >>= static_cast<unsigned long>(this->frontPaddingSize);
				}

				//extract the data element
				bucket.data = packedBuckets % this->dataMessageSpace;

				if (this->backPaddingSize > 0) {
					//shift bits to extract the back padding element
					packedBuckets >>= static_cast<unsigned long>(this->dataSize);

					//extract back padding element
					bucket.backPadding = packedBuckets % this->backPaddingMessageSpace;

					//shift bits to extract the next bucket
					packedBuckets >>= static_cast<unsigned long>(this->backPaddingSize);
				}

				output.emplace_back(bucket);

				/// Compare the number of unpacked buckets to totalBucketCount at each iteration so that we don't unpack more than we should
				if (output.size() == totalBucketCount) {
					return output;
				}

				//debug
				/*
				std::cout << bucket.frontPadding.ToString() << std::endl;
				std::cout << bucket.data.ToString() << std::endl;
				std::cout << bucket.backPadding.ToString() << std::endl;
				std::cout << packedBuckets.ToString() << std::endl;
				*/
			}
		}

		if (output.size() != totalBucketCount) {
			/// @todo Throw a custom exception here
			throw std::runtime_error("Unexpected number of packed buckets.");
		}

		return output;
	}

	/**
	@param lhs left hand side term - a vector of encrypted packed data
	@param rhs right hand side term - a vector of encrypted packed data
	@return A vector of encrypted packed data.
	*/
	template <typename T_CryptoProvider>
	typename DataPacker<T_CryptoProvider>::PackedData DataPacker<T_CryptoProvider>::HomomorphicAdd (const typename DataPacker<T_CryptoProvider>::PackedData &rhs, const typename DataPacker<T_CryptoProvider>::PackedData &lhs) {
		typename DataPacker<T_CryptoProvider>::PackedData output;

		for (typename DataPacker<T_CryptoProvider>::PackedData::const_iterator lhsIterator = lhs.begin(), rhsIterator = rhs.begin(); 
				lhsIterator != lhs.end(), rhsIterator != rhs.end();
				++lhsIterator, ++rhsIterator) {
			output.emplace_back(*lhsIterator + *rhsIterator);
		}

		return output;
	}

	/**
	@param lhs left hand side term - a vector of encrypted packed data
	@param rhs right hand side term - a plaintext integer
	@return A vector of encrypted packed data.
	*/
	template <typename T_CryptoProvider>
	typename DataPacker<T_CryptoProvider>::PackedData DataPacker<T_CryptoProvider>::HomomorphicMultiply (const typename DataPacker<T_CryptoProvider>::PackedData &lhs, const BigInteger &rhs) {
		typename DataPacker<T_CryptoProvider>::PackedData output;

		for (typename DataPacker<T_CryptoProvider>::PackedData::const_iterator lhsIterator = lhs.begin(); lhsIterator != lhs.end(); ++lhsIterator) {
			output.emplace_back(*lhsIterator * rhs);
		}

		return output;
	}
	
	/**
	Initializes the message spaces.

	Computes the size (in bits) of the data bucket.

	Computes the number of buckets that can be packed in one encryption.
	*/
	template <typename T_CryptoProvider>
	void DataPacker<T_CryptoProvider>::initialize () {
		this->dataMessageSpace = BigInteger(1) << static_cast<unsigned long>(this->dataSize);
		this->frontPaddingMessageSpace = BigInteger(1) << static_cast<unsigned long>(this->frontPaddingSize);
		this->backPaddingMessageSpace = BigInteger(1) << static_cast<unsigned long>(this->backPaddingSize);

		this->bucketSize = this->frontPaddingSize + this->dataSize + this->backPaddingSize;

		this->bucketsPerEncryption = this->cryptoProvider.GetMessageSpaceSize() / static_cast<unsigned long>(this->bucketSize);
	}

}//namespace Core
}//namespace SeComLib

#endif//DATA_PACKER_IMPLEMENTATION_GUARD