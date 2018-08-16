/*!
 * \file ros_mac_authentication.cpp
 * \brief Provides authentication via a message authentication codes (MAC).
 *
 * This node provides a service call that can be used to authenticate a user to use the ROS server.
 * The node relies on a hash string that is made up of several pieces of information and hashed
 * using the SHA-1 algorithm. This node is based on the best-practice method of a message
 * authentication codes (MAC).
 *
 * \author Russell Toris, WPI - rctoris@wpi.edu
 * \date March 4, 2013
 */

#include <fstream>
#include <openssl/sha.h>
#include <rclcpp/rclcpp.hpp>
#include <rosauth/srv/authentication.hpp>
#include <sstream>
#include <string>

using namespace std;

/*!
 * \def SECRET_FILE_PARAM
 * The ROS parameter name for the file that contains the secret string. We do not store the actual
 * string in the parameter server as the parameter server itself may not be secure.
 */
#define SECRET_FILE_PARAM "/ros_mac_authentication/secret_file_location"

/*!
 * \def MISSING_PARAMETER
 * Error code for a missing SECRET_FILE_PARAM ROS parameter.
 */
#define MISSING_PARAMETER -1

/*!
 * \def FILE_IO_ERROR
 * Error code for an IO error when reading the secret file.
 */
#define FILE_IO_ERROR -2

/*!
 * \def INVALID_SECRET
 * Error code for an invalid secret string.
 */
#define INVALID_SECRET -3

/*!
 * \def SECRET_LENGTH
 * Length of the secret string.
 */
#define SECRET_LENGTH 16

// the secret string used in the MAC
string secret;

class ServerNode : public rclcpp::Node
{
public:
  explicit ServerNode(const string & node_name)
  : Node(node_name)
  {}

  bool authenticate(
    rosauth::srv::Authentication::Request::SharedPtr req,
    rosauth::srv::Authentication::Response::SharedPtr res
  ) {
    // keep track of the current time
    auto t = this->now();
    auto req_t = rclcpp::Time(req->t);
    // clocks can be out of sync, check which comes later
    rclcpp::Duration diff(0, 0);
    if (req_t > t)
      diff = req_t - t;
    else
      diff = t - req_t;
    bool time_check = diff.nanoseconds() < 5000000000 && rclcpp::Time(req->end) > t;

    // check if we pass the time requirement
    if (time_check)
    {
      // create the string to hash
      stringstream ss;
      ss << secret << req->client << req->dest << req->rand << req->t.sec << req->level << req->end.sec;
      string local_hash = ss.str();

      // check the request
      unsigned char sha512_hash[SHA512_DIGEST_LENGTH];
      SHA512((unsigned char *)local_hash.c_str(), local_hash.length(), sha512_hash);

      // convert to a hex string to compare
      char hex[SHA512_DIGEST_LENGTH * 2];
      for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        sprintf(&hex[i * 2], "%02x", sha512_hash[i]);

      // an authenticated user must match the MAC string
      res->authenticated = (strcmp(hex, req->mac.c_str()) == 0);
    }
    else
      res->authenticated = false;

    return true;
  }
};

/*!
 * Creates and runs the ros_mac_authentication node.
 *
 * \param argc argument count that is passed to ros::init
 * \param argv arguments that are passed to ros::init
 * \return EXIT_SUCCESS if the node runs correctly
 */
int main(int argc, char **argv)
{
  // initialize ROS and the node
  rclcpp::init(argc, argv);
  auto node = std::make_shared<ServerNode>("ros_mac_authentication");

  // check if we have to check the secret file
  rclcpp::Parameter file;
  if (!node->get_parameter(SECRET_FILE_PARAM, file))
  {
    RCLCPP_ERROR(node->get_logger(), "Parameter '%s' not found.", SECRET_FILE_PARAM);
    return MISSING_PARAMETER;
  }
  else
  {
    // try and load the file
    ifstream f;
    f.open(file.as_string().c_str(), ifstream::in);
    if (f.is_open())
    {
      // should be a 1 line file with the string
      getline(f, secret);
      f.close();
      // check the length of the secret
      if (secret.length() != SECRET_LENGTH)
      {
        RCLCPP_ERROR(node->get_logger(), "Secret string not of length %d.", SECRET_LENGTH);
        return INVALID_SECRET;
      }
      else
      {
        auto service = node->create_service<rosauth::srv::Authentication>(
          "authenticate", std::bind(&ServerNode::authenticate, node, placeholders::_1, placeholders::_2));
        RCLCPP_INFO(node->get_logger(), "ROS Authentication Server Started");
        rclcpp::spin(node);

        return EXIT_SUCCESS;
      }
    }
    else
    {
      RCLCPP_ERROR(node->get_logger(), "Could not read from file '%s'", file.as_string().c_str());
      return FILE_IO_ERROR;
    }
  }
}
