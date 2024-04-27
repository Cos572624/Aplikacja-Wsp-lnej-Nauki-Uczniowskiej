<?php

include 'connect.php';
include 'header.php';

// Check if $_GET['id'] is set and is a valid integer
if (isset($_GET['id']) && is_numeric($_GET['id'])) {
    // Select the category based on $_GET['id']
    $cat_id = intval($_GET['id']);

    $sql = "SELECT cat_id, cat_name, cat_description
            FROM categories
            WHERE cat_id = $cat_id";

    $result = mysqli_query($conn, $sql);

    if (!$result) {
        echo 'The category could not be displayed, please try again later.' . mysqli_error($conn);
    } else {
        if (mysqli_num_rows($result) == 0) {
            echo 'This category does not exist.';
        } else {
            // Display category data
            $row = mysqli_fetch_assoc($result);
            echo '<h2>Topics in ' . $row['cat_name'] . ' category</h2>';

            // Do a query for the topics
            $sql = "SELECT topic_id, topic_subject, topic_date, topic_cat
                    FROM topics
                    WHERE topic_cat = $cat_id";

            $result = mysqli_query($conn, $sql);

            if (!$result) {
                echo 'The topics could not be displayed, please try again later.';
            } else {
                if (mysqli_num_rows($result) == 0) {
                    echo 'There are no topics in this category yet.';
                } else {
                    // Prepare the table
                    echo '<table border="1">
                            <tr>
                                <th>Topic</th>
                                <th>Created at</th>
                            </tr>';

                    while ($row = mysqli_fetch_assoc($result)) {
                        echo '<tr>';
                        echo '<td class="leftpart"><h3><a href="topic.php?id=' . $row['topic_id'] . '">' . $row['topic_subject'] . '</a><h3></td>';
                        echo '<td class="rightpart">' . date('d-m-Y', strtotime($row['topic_date'])) . '</td>';
                        echo '</tr>';
                    }
                }
            }
        }
    }
} else {
    // Handle the case when $_GET['id'] is not set or not a valid integer
    echo 'Invalid category ID.';
}

include 'footer.php';

?>
