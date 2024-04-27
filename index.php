<?php

// create_cat.php

include 'connect.php';

include 'header.php';

$sql = "SELECT DISTINCT

categories.cat_id,

categories.cat_name,

categories.cat_description,

topics.topic_date as 'latest',

topics.topic_id

FROM

categories
LEFT JOIN topics ON categories.cat_id = topics.topic_cat

";

$result = mysqli_query($conn, $sql);

if (!$result) {

    echo 'The categories could not be displayed, please try again later.';

} else {

    if (mysqli_num_rows($result) == 0) {

        echo 'No categories defined yet.';

    } else {


        echo '<table border="1">

<tr>

<th>Category</th>

<th>Last topic</th>

</tr>';

        while ($row = mysqli_fetch_assoc($result)) {

            echo '<tr>';

            echo '<td class="leftpart">';

            echo '<h3><a href="category.php?id=' . $row['cat_id'] . '">' . $row['cat_name'] . '</a>: ' . '</h3>' .'<p>'. $row['cat_description'] . '</p>';

            echo '</td>';

            echo '<td class="rightpart">';

            echo '<a href="topic.php?id=' . $row['topic_id'] . '">' . $row['latest']. '</a>';

            echo '</td>';

            echo '</tr>';

        }

    }

}

include 'footer.php';

?>
