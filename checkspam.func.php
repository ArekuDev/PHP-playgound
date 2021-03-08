<?php
function checkSpam($email,$phone,$comments,$dealer="", $notifyAddress="",$mode="warning", $threshold=2){
	/**
	* Checks form input for common spammy indicators and sends an e-mail if a form submission might be spam
	@param string 	$email 			User's email
	@param string 	$phone 			User's Phone (accepts digits and chars)
	@param string 	$comments 		User's comments
	@param string 	$dealer 		Dealer's ID 
	@param string 	$notifyAddress	Dealer's email address to send a copy of spam notification to. Default NULL
	@param string 	$mode 			"warning" = (default) sends a warning email but allows the comment to post.
									"enforce" = sends e-warning mail, and blocks the message from going through.
	@param int 		$threshold		IF $mode =='enforce', the number of "spammy" indicators that must be true to
										block the message. Default 2.
	@return array|bool				Returns array of reasons this message might be spam.
									If message is spam, threshold is met, and mode=='enforce' the first value in
										the returned array will be "BLOCK"
									Returns false if message looks OK.
	/*****************************/
		$maybeSpam = array();
	// set the hours to send e-mails (so we don't get a shit-ton overnight and on weekends)
		if( date("w") > 0 && date("w") < 6 && date("H") >=9 && date("H") < 17 )
			$isDuringBizHours = true;
	// check against known suspicious domains
		$spamEmails = array("\.ru","\.yandex","\.cn","\.talkwithcustomer\.com");
		if(preg_match('/('.implode('|', $spamEmails).')$/i', $r_email)){
			$maybeSpam[]="E-mail domain is suspicious.";
		}
	/*** This section is remmed out until we can look into issues with the API timing out.
	// Check this e-mail address's reputation (see dox at https://emailrep.io/ )
		// To test a bad e-mail use: bsheffield432@gmail.com
		$ts1=time();
		$url = "http://emailrep.io/$email";
		$options = array( 'http' => array(
		      'max_redirects' => 1,
		      'timeout'       => 5,
		  ) );
		$context = stream_context_create( $options );
		$content = file_get_contents( $url, false, $context );
		$emailReputation = json_decode($content,true);
		//$emailReputation = json_decode(file_get_contents("http://emailrep.io/$email"),true);
		$ts2=time();
		if($content !== false) {
			if($emailReputation['suspicious'] == true) {
				$maybeSpam[] = "EmailRep.io identified this email as suspicious.";
				if($emailReputation['details']["blacklisted"] != false) { $maybeSpam[]="Email has been blacklisted."; }
				if($emailReputation['details']["malicious_activity"] != false) { $maybeSpam[]="Email known for malicious activity."; }
				if($emailReputation['details']["malicious_activity_recent"] != false) { $maybeSpam[]="Email has recent history of malicious activity."; }
				if($emailReputation['details']["credentials_leaked"] != false) { $maybeSpam[]="Credentials leaked for this email."; }
				if($emailReputation['details']["data_breach"] != false) { $maybeSpam[]="Email was data breached."; }
				if($emailReputation['details']["domain_exists"] != true) { $maybeSpam[]="Email domain is not valid."; }
				if($emailReputation['details']["suspicious_tld"] != false) { $maybeSpam[]="Email domain is suspicious."; }
				if($emailReputation['details']["spam"] != false) { $maybeSpam[]="Email is known for Spammy behavior."; }
				if($emailReputation['details']["free_provider"] != false) { $maybeSpam[]="Email uses a free provider."; }
				if($emailReputation['details']["disposable"] != false) { $maybeSpam[]="Email is a disposable address."; }
				if($emailReputation['details']["deliverable"] != true) { $maybeSpam[]="Email is not deliverable."; }
				if($emailReputation['details']["valid_mx"] != true) { $maybeSpam[]="Email does not have a valid MX record"; }
				if($emailReputation['details']["spoofable"] == true) { $maybeSpam[]="Email can be spoofed (e.g. not a strict SPF policy or DMARC is not enforced";}
				if(empty($emailReputation['details']["profiles"])) { $maybeSpem[] = "Email has no known profiles on major social media networks.";}
			} // if suspicious
		}// if !empty emailReputation
		else { // if emailReputation was false, that means the API request timed out.
			mail("<EMAIL ADDRESS HERE>","emailRep API timed out","checkSpamFunction aborted the EmailRep.io API call because it took too long. (".($ts2-$ts1)." seconds).\n\n Location: ".$_SERVER['SCRIPT_FILENAME']." at line ". __LINE__ .". \n\n POST: ".print_r($_POST,true));
		}
		/**  End email reputation code  **/
		//not all forms require phone numbers (e.g. tellfriend), so skip this part if there is no $phone
		if($phone >''){
			// Test for more then 5 repeated digits in the phone number
			$phoneRegex = "(\d)(\1){4,}";
			if(preg_match("/$phoneRegex/",preg_replace("/^D/","",$phone))){
				$maybeSpam[] = "Phone number contains 5 or more repeated digits.";
				echo "Phone number $phone <br>";
				echo 'preg_match("/'.$phoneRegex.'/",preg_replace("/^D/","",'.$phone.')) <br>';
				echo preg_replace("/^D/","",$phone);
			}
			// Test to see if number is a valid U.S. phone number
			$phoneNumberRegex = "^(?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?([2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?([0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(\d+))?$";
			if(!preg_match("/$phoneNumberRegex/",$phone)) {
				$maybeSpam[] = "Phone number not a valid U.S. number.";
			}
		}
		if($email >"") { // test to see if e-mail is a valid address
			$regex="^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$";
			if(!preg_match("/$regex/",$email)){
				$maybeSpam[] = "Email does not seem valid.";
			}
		}
		if($comments > "") { // to prevent false positives if there are no comments
			// Test to see if more than 20% of the content contains foriegn or extended non-ASCII characters.
				$extCharactersRegex = "([^\sA-Za-z0-9';.,!\$%&()’“”])";
				preg_match_all("/$extCharactersRegex/",$comments,$extMatches);
				$numExtChars = sizeof($extMatches[0]);
				$lengthComments = strlen($comments);
				$ratio = $numExtChars / $lengthComments;
				if($ratio > 0.20){
					$maybeSpam[] = "Large amount of foriegn or non-letter characters.  Ratio of ext. chars ($numExtChars) to total chars ($lengthComments) is ".number_format($ratio,2)."  Threshold is .20";
				}
			// Test to see if the comments contains a link
				$urlRegex="/(http|ftp|https):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-]*[\w@?^=%&\/~+#-])?/i";
				if(preg_match("$urlRegex",$comments)){
					$maybeSpam[] = "Comments contains a URL";
				}
			// Test to see if comments contain pre-determined "Bad text"
				$badText = array ( "FeedbackFormEU", "FeedbackForm2019", "make-success.com","formblasting", "@FeedbackMessages", "make-success@mail.ru", "TERMINATION OF DOMAIN" );
				foreach($badText as $badword){
					$find = preg_match("/$badword/",$comments);
					if($find > 0){
						$maybeSpam[]="Text contains spammy word: '$badword'";
						$mode="enforce";
						$kill = true;
						break;
					}
				}
			// See If comments contains an e-mail AND that e-mail is different than the given e-mail address.
		}
		// Build the warning message
		if(sizeof($maybeSpam)>0) {
			$spamWarning = "This message was flagged based on the following criteria:<p>";
			foreach($maybeSpam as $reason){
				$spamWarning .= "- $reason \r\n";
			}
			$spamWarning .= "</P>From IP:  ".$_SERVER['REMOTE_ADDR'];
			////  Log this spam to the database.
				include "<< DATABASE CONNECTION INCLUDE HERE >>";
				preg_match("/^.*(@\w+\.\w+)/",$email,$tld);
				if($kill==true) $status = "red";
				else $status="grey";
				$addSql = "INSERT INTO `SpamTracker` (`IP`, `Email`, `LastSeen`, `CameFrom`, `TLD`, `Dealer`, `SpamScore`, `SpamReasons`,`SpamContent`,`FullPost`,`FromPage`,`Status`) VALUES ('".$_SERVER['REMOTE_ADDR'] . "', '$email', CURRENT_TIMESTAMP, '".$_SERVER['SCRIPT_FILENAME']."', '".$tld[1]."', '$dealer', '".sizeof($maybeSpam)."', '" . mysqli_real_escape_string($conn00, json_encode($maybeSpam))."','". mysqli_real_escape_string($conn00,$comments)."', '" .  mysqli_real_escape_string($conn00, json_encode($_POST)) . " ', '" . $_SERVER['SCRIPT_FILENAME'] . "','$status');";
				$addQry = mysqli_query($conn00,$addSql);
				if(!$addQry || mysqli_error($conn00)) mail("<<EMAIL ADDRESS HERE>>","ERROR: checkspam error Mysql ",mysqli_error($conn00)." \n ".mysqli_connect_error()."\n$addSql \n checkSpamFunction".__LINE__);
				$spamID = mysqli_insert_id($conn00);
				mysqli_close($conn00);
			//// Send email notification
			$mailTo = "<< EMAIL ADDRESS HERE >>";
			$mailHeaders =  "MIME-Version: 1.0\nContent-type: text/html; charset=UTF-8\n";
			$mailStyle = " * {font-face:arial}
			.red {background-color:red;}
			.green {background-color:#080;}
			.btn { border:none; border-radius:8px; padding:4px;}
			a.btn { color:#fff; text-decoration:none; font-weight: bold;}
			";
			$mailBody =  "<html><head><style>$mailStyle</style></head><body>";
			$mailBody .= "Dealer $dealer received a lead that may be spam.";
			if($kill) {
				$mailBody .= '<P class="red"> THIS MESSAGE WAS BLOCKED and STATUS AUTO-SET to "CONFIRMED SPAM".</p>';
			} else {
				$mailBody .= '<P><a href = "<< DOMAIN >> spamtracker.php?updateid='.$spamID.'&status=red" class="btn red">CONFIRM SPAM</a>';
				$mailBody .= '<a href = "<< DOMAIN >> /spamtracker.php?updateid='.$spamID.'&status=green" class="btn green"> This is not Spam</a> </p> ';
			}
			$mailBody .= '<P> <a href="<< DOMAIN >>spamtracker.php?id='.$spamID.'">Manage/Edit this listing</a> </P>';
			$mailBody .= "<p> ". str_replace("\r\n","<br>",$spamWarning) ." </P> checkSpam function received: <BR> email: $email<BR>Phone: $phone<BR>Comments: $comments<BR>Dealer: $dealer<BR>notifyAddress:$notifyAddress<BR> mode: $mode<BR>Threshold: $threshold </P>
				FULL POST:<pre>".print_r($_POST,true)."</pre> <P> generated by ".$_SERVER['SCRIPT_FILENAME'].". </body></html>";
			if($notifyAddress>'') $mailto.=",$notifyAddress";
			if(!$debug && $isDuringBizHours) {
				mail($mailTo,"Possible spam from website lead",$mailBody,$mailHeaders);
			}
			// if mode=="enforce" block the mail from sending if sizeof($maybeSpam) > threshold
			if(($mode=='enforce' && sizeof($maybeSpam) >= $threshold) || $kill == true) {
				array_unshift($maybeSpam,"BLOCK");
				die("Thank You. Your message was sent. <a href=/>Back to site</a>");
			}
			return $maybeSpam;
		} else {
			return false;
		}
	}// fn checkSpam
?>
