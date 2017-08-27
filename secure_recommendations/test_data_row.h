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
@file secure_recommendations/test_data_row.h
@brief Definition of struct TestDataRow.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef TEST_DATA_ROW_HEADER_GUARD
#define TEST_DATA_ROW_HEADER_GUARD

//include our headers
#include "secure_svm.h"

namespace SeComLib {
namespace SecureRecommendations {
	/**
	@brief Processed test data container
	*/
	struct TestDataRow {
	public:
		/// Encrypted test data vector
		SecureSvm::EncryptedVector x;

		/// Encrypted vector product combinations, @f$ x_i x_j @f$, stored as an unraveled upper triangular matrix
		SecureSvm::EncryptedVector xx;

		/// Encrypted squared test data vector
		SecureSvm::EncryptedVector xSquared;

		/// The expected cluster (use this for accuracy measures)
		unsigned short clusterLabel;

		/// The quality of life measure (use this for accuracy measures)
		char qualityOfLifeLabel;
	};

}//namespace SecureRecommendations
}//namespace SeComLib

#endif//TEST_DATA_ROW_HEADER_GUARD