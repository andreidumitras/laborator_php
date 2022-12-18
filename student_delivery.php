<?php
	/* 
	IMPORTANT - PLEASE READ ME
		This is the ONLY file that I will use to validate your solution's implementation. Please keep in mind that only the changes done to this file
		will be tested, and if you modify anything in any other files those changes won't be taken in account when I validate your solution.
		Also, please do not rename the file.

		In a separate file (named answers.txt) answer the following questions for each function you implement:
			* What vulnerabilities can there be in that function 
				(take in account the fact that the function may not be vulnerable and explicitly say so if you consider it to be that way)
			* What specific mitigation you used for each of the vulnerabilities listed above
		
		For the function named 'get_language_php' which is already implemented make sure to answer and do all the steps required that are listed
		above the implementation.

	DELIVERY REQUIREMENTS
		When delivering your solution, please ensure that you create a .zip archive file (make sure it's zip, not 7z, rar, winzip, etc)
		with the name "LastnameFirstname.zip" (for example MunteaAndrei.zip or RatiuRazvan.zip) and in the root of the zip file please 
		add the student_delivery.php file modified by you (keep the name as it is) and answers.txt file where you answered the questions.
	*/

	/* Implement query_db_login - this function is used in login.php */
	/* 
		Description - Must query the database to obtain the username that matches the 
		input parameters ($username, $password), or must return null if there is no match.
		The password is stored as MD5, so the query must convert the password received as parameter to
		MD5 and AFTER that interogate the DB with the MD5.
		PARAMETERS:
			$username: username field from post request
			$password: password field from post request
		MUST RETURN:
			null - if user credentials are not correct
			username - if credentials match a user
	*/


	// function that checks is the string passed as parameter has an xss inside.
	function xss($str)
	{
		if (strchr($str, "<") != "" && strchr($str,">") != "")
			return true;
		return false;
	}

	// we recieve the username and its password.
	// we hash the password
	// we compare the hashed password with one stored inside the database for the given username. 

	function query_db_login($username, $password) 
	{
		// try?
		$conn = get_mysqli();
		$found = null;

		// encrypt the password using md5
		$pass_hashed = md5($password);
		$query = "SELECT username, password FROM users WHERE username = ? AND password = ?";
		$stmt = $conn->prepare($query);
		$stmt->bind_param("ss", $username, $pass_hashed);           // ss = string, string
		$stmt->execute();
		$result = $stmt->get_result();

		$row1 = $result->fetch_assoc();
		// echo $row1["username"] . "<br>" . $row1["password"];

		if (count($row1) <= 0)
		{
			$conn->close();
			return null;
		}
		$found = $row1["username"];
		$conn->close();
		return $found;
	}

	/* Implement get_message_rows - this function is used in index.php */
	/* 
		Function must query the db and fetch all the entries from the 'messages' table
		(username, message - see MUST RETURN for more details) and return them in a separate array, 
		or return an empty array if there are no entries.
		PARAMETERS:
			No parameters
		MUST RETURN:
			array() - containing each of the rows returned by mysqli if there is at least one message
					  (code will use both $results['username'] and $results['message'] to display the data)
			empty array() - if there are NO messages
	*/
	function get_message_rows() 
	{
		$conn = get_mysqli();
		$results = array();

		$query = "SELECT username, message FROM messages";
		$stmt = $conn->prepare($query);
		// $stmt->bind_param("ss", $username, $pass_hashed);           // ss = string, string
		$stmt->execute();
		$res = $stmt->get_result();
		$results = $res->fetch_all(MYSQLI_ASSOC);

		$conn->close();
		return $results;
	}
	
	/* Implement add_message_for_user - this function is used in index.php */
	/* 
		Function must add the message received as parameter to the database's 'message' table.
		PARAMETERS:
			$username - username for the user submitting the message
			$message - message that the user wants to submit
		MUST RETURN:
			Return is irrelevant here
	*/
	function add_message_for_user($username, $message) 
	{
		if ($message != null)
		{
			$conn = get_mysqli();
			//$results = array();
			if (xss($message))
			{
				$conn->close();
				exit;
			}
			$query = "INSERT INTO messages (username, message) VALUES (?, ?)";
			$stmt = $conn->prepare($query);
			$stmt->bind_param("ss", $username, $message);           // ss = string, string
			$stmt->execute();

			$conn->close();
		}
	}

	/* Implement is_valid_image - this function is used in index.php */
	/* 
		This function will validate if the file contained at $image_path is indeed an image.
		PARAMETERS:
			$image_path: path towards the file on disk
		MUST RETURN:
			true - file is an image
			false - file is not an image
	*/
	function is_valid_image($image_path)
	{
		if ($image_path != null)
		{
			$finfo = finfo_open(FILEINFO_MIME_TYPE);
			$supported_images = array("jpg", "jpeg", "png", "gif", "bmp", "ico");
			$type = finfo_file($finfo, $image_path);
			foreach ($supported_images as $extension)
			{
				$extension = "image/" . $extension;
				if ($type == $extension)
				{
					finfo_close($finfo);
					return true;					
				}
			}
			finfo_close($finfo);
			return false;
		}
	}

	/* Implement add_photo_to_user - this function is used in index.php */
	/* 
		This function must update the 'users' table and set the 'file_userphoto' field with 
		the value given to the $file_userphoto parameter
		PARAMETERS:
			$username - user for which to update the row
			$file_userphoto - value to be put in the 'file_userphoto' column (a path to an image)
		MUST RETURN:
			Return is irrelevant here
	*/
	function add_photo_path_to_user($username, $file_userphoto) 
	{
		$conn = get_mysqli();
		if (!is_valid_image($file_userphoto))
		{
			$conn->close();
			echo "Something is not appropriate with the photo: " . $file_userphoto;
			return;
		}
		$query = "UPDATE users SET file_userphoto = ? WHERE username = ?";
		$stmt = $conn->prepare($query);
		$stmt->bind_param("ss", $file_userphoto, $username);           // ss = string, string
		$stmt->execute();

		$conn->close();
	}

	/* Implement get_photo_path_for_user - this function is used in index.php */
	/* 
		This function must obtain from the 'users' table the field named file_userphoto and
		return is as a string. If there is nothing in the database, then return null.
		PARAMETERS:
			$username - user for which to query the file_userphoto column
		MUST RETURN:
			string - string containing the value from the DB, if there is such a value
			null - if there is no value in the DB
	*/
	function get_photo_path_for_user($username) 
	{
		$conn = get_mysqli();
		$path = "";

		$query = "SELECT file_userphoto FROM users WHERE (username = ?)";
		$stmt = $conn->prepare($query);
		$stmt->bind_param("s", $username);           // ss = string, string
		$stmt->execute();
		$result = $stmt->get_result()->fetch_assoc();
		if (count($result) <= 0)
		{
			$conn->close();
			return null;
		}
		$path = $result["file_userphoto"];
		$conn->close();
		echo $path . '<br>';
		return $path;
	}

	/* Implement get_memo_content_for_user - this function is used in index.php */
	/* 
		This function must open the memo file for the current user from it's folder and return its content as a string.
		If the memo does not exist, the function must return the string "No such file!".
		PARAMETERS:
			$username - user for which obtain the memo file
			$memoname - the name of the memo the user requested to see
		MUST RETURN:
			string containing the data from the memo file (it's content)
			"No such file!" if there's no such file.
	*/
	function get_memo_content_for_user($username, $memoname)
	{
		if (strchr($memoname, "/") || strchr($memoname, "\\" ))
		{
			echo "Suspect file name." . "<br>";
			echo "Try to refer only by the memo name that you stored." . "<br>";
			return "";
		}
		$path = "users/" . $username . "/" . $memoname;
		echo $path;
		$content = file_get_contents($path);
		if (!$content)
			return "No such file!";
		return nl2br($content);
	}

	/* 
		Evaluate the impact of 'get_language_php' by explaining what are the risks of this function's default implementation
		(the one you received) by answering the following questions:
			- What is the vulnerability present in this function?
			- What other vulnerability can be chained with this vulnerability to inflict damage on the web application and where is it present?
			- What can the attacker do once he chains the two vulnerabilities?
		After that, modify the get_language_php function to no longer present a security risk.
		This function is used in index.php
	*/
	
	/*
		This function must return the path to the language file corresponding to the desired language or null if the file
		does not exist. All language files must be in the language folder or else they are not supported.
		PARAMETERS:
			$language - desired language (e.g en)
		MUST RETURN:
			path to the en language file (languages/en.php)
			null if the language is not supported
	*/
	function get_language_php($language)
	{
		if (strchr($language, "/") || strchr($language, "\\" ))
		{
			echo "The language that you set is suspect" . "<br>";
			echo "Try to refer only to the supported languages [en, ro]." . "<br>";
			return null;
		}
		$language_path = "language/" . $language . ".php";
		if (is_file($language_path))
		{
			return $language_path;
		}
		return null;
	}
?>
