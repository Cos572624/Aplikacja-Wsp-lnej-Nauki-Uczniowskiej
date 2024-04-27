<?php

// create_cat.php
include 'connect.php';
include 'header.php';


echo '<h2>Create a category</h2>';

if($_SESSION['signed_in'] == false)

{

    //the user is not signed in

    echo 'Sorry, you have to be <a href="/forum/signin.php">signed in</a> to create a topic.';

}

else

{


if ($_SERVER['REQUEST_METHOD'] != 'POST') {

    // The form hasn't been posted yet, display it

    echo "<form method='post' action=''>

Category name: <input type='text' name='cat_name' />

Category description: <textarea name='cat_description'></textarea>

<input type='submit' value='Add category' />

</form>";

} else {

    // The form has been posted, so save it

    $cat_name = $_POST['cat_name'];

    $cat_description = $_POST['cat_description'];

    // Prepare the SQL statement with placeholders

    $sql = "INSERT INTO categories (cat_name, cat_description)

VALUES (?, ?)";

    // Create a prepared statement

    $stmt = mysqli_prepare($conn, $sql);

    // Bind parameters to the prepared statement

    mysqli_stmt_bind_param($stmt, 'ss', $cat_name, $cat_description);

    // Execute the prepared statement

    $result = mysqli_stmt_execute($stmt);

    if (!$result) {

        // Something went wrong, display the error

        echo 'Error: ' . mysqli_error($conn);

    } else {

        echo 'New category successfully added.';

    }

    // Close the prepared statement

    mysqli_stmt_close($stmt);

}
}
include 'footer.php';
?>
