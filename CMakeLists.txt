cmake_minimum_required(VERSION 3.5)
project(rosauth)

find_package(ament_cmake_core REQUIRED)
find_package(builtin_interfaces REQUIRED)
find_package(rclcpp REQUIRED)
find_package(rosidl_default_generators REQUIRED)

rosidl_generate_interfaces(${PROJECT_NAME}
  srv/Authentication.srv
  DEPENDENCIES builtin_interfaces
)

add_executable(ros_mac_authentication src/ros_mac_authentication.cpp)
add_dependencies(ros_mac_authentication ${PROJECT_NAME})
ament_target_dependencies(ros_mac_authentication rclcpp)
rosidl_target_interfaces(
  ros_mac_authentication ${PROJECT_NAME} "rosidl_typesupport_cpp")
target_link_libraries(ros_mac_authentication crypto)

ament_export_dependencies(rosidl_default_runtime)

ament_package()

install(TARGETS ros_mac_authentication
  RUNTIME DESTINATION lib/${PROJECT_NAME}
)

if(BUILD_TESTING)
  ## Add gtest based cpp test target and link libraries
  # TODO reenable rostests
  # add_executable(ros_mac_authentication_test test/ros_mac_authentication_test.cpp)
  # add_dependencies(ros_mac_authentication_test ${PROJECT_NAME}_gencpp)
  # target_link_libraries(ros_mac_authentication_test ${catkin_LIBRARIES} ${GTEST_LIBRARIES} crypto dl pthread)
  # add_rostest(test/ros_mac_authentication.test)
endif()
