<?php

//create_cat.php

include 'connect.php';

include 'header.php';

if($_SERVER['REQUEST_METHOD'] != 'POST')

{

    //someone is calling the file directly, which we don't want

    echo 'This file cannot be called directly.';

}

else

{

	//check for sign in status

	if(!$_SESSION['signed_in'])

	{

		echo 'You must be signed in to post a reply.';

	}

	else

	{

		//a real user posted a real reply

		$sql = "INSERT INTO

posts(post_content,

post_date,

post_topic,

post_by)

VALUES (?, NOW(), ?, ?)";

		$stmt = mysqli_prepare($conn, $sql);

		mysqli_stmt_bind_param($stmt, "sii", $_POST['reply-content'], $_GET['id'], $_SESSION['user_id']);

		mysqli_stmt_execute($stmt);

		if(mysqli_stmt_errno($stmt))

		{

			echo 'Your reply has not been saved, please try again later.';

		}

		else

		{

			echo 'Your reply has been saved, check out <a href="topic.php?id=' . htmlentities($_GET['id']) . '">the topic</a>.';

		}

	}

}

include 'footer.php';

?>
