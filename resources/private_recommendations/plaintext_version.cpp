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
@file plaintext_version.cpp
@brief Plaintext implementation for "Generating Private Recommendations Efficiently Using Homomorphic Encryption and Data Packing", Zekeriya Erkin, Thijs Veugen, Tomas Toft, and Reginald L. Lagendijk, 2012
@author Mihai Todor (todormihai@gmail.com)
*/
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <ctime>
#include <cmath>

#define GENERATE_RATINGS1

int main ()
{
	//define constants
	size_t userCount = 10;
	size_t itemCount = 10;
	size_t denselyRatedItemCount = 5;
	double similarityThreshhold = 0.87;

#ifdef GENERATE_RATINGS//generate random ratings
	/// Generate dummy ratings

	//initialize random seed
	srand (static_cast<unsigned int>(time(NULL)));

	std::stringstream userCountStr; userCountStr << userCount;
	std::ofstream ratingsFile(std::string("ratings") + userCountStr.str() + ".txt", std::ios::trunc);
	
	/// Generate dummy database
	std::vector<std::vector<unsigned int>> ratings;
	ratings.reserve(userCount);
	for (size_t user = 0; user < userCount; ++user)
	{
		std::vector<unsigned int> userRatings;
		userRatings.reserve(itemCount);

		// write densely related items
		for (size_t item = 0; item < denselyRatedItemCount; ++item)
		{
			// generate random numbers between 1 and 5
			userRatings.emplace_back(static_cast<unsigned int>(rand() % 5 + 1));

			//write to file
			ratingsFile << userRatings.back() << " ";
		}

		// write the sparse items
		for (size_t item = 0; item < itemCount - denselyRatedItemCount; ++item)
		{
			// generate random numbers between 0 and 5 (with a 50% chance that it ends up being 0)
			int random = rand() % 2;
			if (random == 0)
			{
				userRatings.emplace_back(0);
			}
			else
			{
				userRatings.emplace_back(static_cast<unsigned int>(rand() % 5 + 1));
			}

			//write to file
			ratingsFile << userRatings.back() << " ";
		}

		ratings.emplace_back(userRatings);

		//write line terminator
		ratingsFile << std::endl;
	}

	std::cout << "Finished generating ratings." << std::endl;

#else
	
	std::stringstream userCountStr; userCountStr << userCount;
	std::ifstream ratingsFile(std::string("ratings") + userCountStr.str() + ".txt");

	std::vector<std::vector<unsigned int>> ratings;
	ratings.reserve(userCount);
	std::string line;
	while (std::getline(ratingsFile, line))//foreach user
	{
		std::istringstream lineStream(line);

		std::vector<unsigned int> userRatings;
		userRatings.reserve(itemCount);

		for (size_t item = 0; item < denselyRatedItemCount; ++item)
		{
			//fetch the value
			unsigned int rating;
			lineStream >> rating;

			userRatings.emplace_back(rating);
		}

		unsigned long rating;
		while (lineStream >> rating)
		{
			userRatings.emplace_back(rating);
		}

		ratings.emplace_back(userRatings);
	}

	/// Compute similarities
	std::vector<std::vector<bool>> similarities;
	ratings.reserve(userCount);
	for (size_t userA = 0; userA < userCount; ++userA)
	{
		std::vector<bool> userSimilarities;
		userSimilarities.reserve(userCount - 1);

		for (size_t userB = 0; userB < userCount; ++userB)
		{
			if (userA != userB)
			{
				unsigned long numerator = 0;
				unsigned long denominatorA = 0, denominatorB = 0;
				for (size_t item = 0; item < denselyRatedItemCount; ++item)
				{
					numerator += ratings[userA][item] * ratings[userB][item];

					denominatorA += ratings[userA][item] * ratings[userA][item];

					denominatorB += ratings[userB][item] * ratings[userB][item];
				}

				double similarityValue = static_cast<double>(numerator) / sqrt(static_cast<double>(denominatorA) * static_cast<double>(denominatorB));

				userSimilarities.push_back(similarityValue >= similarityThreshhold ? true : false);
			}
		}

		similarities.emplace_back(userSimilarities);
	}

	std::cout << "Finished computing similarities." << std::endl;


	std::ofstream recommendationsFile("recommendations.txt", std::ios::trunc);

	/// Compute recommendations
	for (size_t userA = 0; userA < userCount; ++userA)
	{
		size_t L = 0;
		for (size_t similarity = 0; similarity < similarities[userA].size(); ++ similarity)
		{
			if (similarities[userA][similarity] == true)
			{
				++L;
			}
		}

		recommendationsFile << "User: " << userA << "; L = " << L;

		if (L > 0)
		{
			recommendationsFile << "; Recommendations:" << std::endl;

			for (size_t item = 0; item < itemCount - denselyRatedItemCount; ++item)
			{
				size_t recommendation = 0;
				for (size_t userB = 0; userB < userCount; ++userB)
				{
					if (userA > userB)
					{
						recommendation += (similarities[userA][userB] == true ? 1 : 0) * ratings[userB][denselyRatedItemCount + item];
					}
					else if (userA != userB)
					{
						recommendation += (similarities[userA][userB - 1] == true ? 1 : 0) * ratings[userB][denselyRatedItemCount + item];
					}
				}

				recommendationsFile << static_cast<double>(recommendation) / static_cast<double>(L) << std::endl;
			}
		}
		else
		{
			recommendationsFile << std::endl;
		}
	}

	std::cout << "Finished computing recommendations." << std::endl;

#endif

	return 0;
}