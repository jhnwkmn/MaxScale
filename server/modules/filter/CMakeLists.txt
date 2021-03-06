if(BUILD_RABBITMQ)
  find_package(RabbitMQ)
  include_directories(${RABBITMQ_HEADERS})
  add_library(mqfilter SHARED mqfilter.c)
  target_link_libraries(mqfilter query_classifier log_manager utils ${RABBITMQ_LIBRARIES})
  install(TARGETS mqfilter DESTINATION modules)
endif()

add_library(regexfilter SHARED regexfilter.c)
target_link_libraries(regexfilter log_manager utils)
install(TARGETS regexfilter DESTINATION modules)

add_library(testfilter SHARED testfilter.c)
target_link_libraries(testfilter log_manager utils)
install(TARGETS testfilter DESTINATION modules)

add_library(qlafilter SHARED qlafilter.c)
target_link_libraries(qlafilter log_manager utils)
install(TARGETS qlafilter DESTINATION modules)

add_library(tee SHARED tee.c)
target_link_libraries(tee log_manager utils)
install(TARGETS tee DESTINATION modules)

add_library(topfilter SHARED topfilter.c)
target_link_libraries(topfilter log_manager utils)
install(TARGETS topfilter DESTINATION modules)

add_library(dbfwfilter SHARED dbfwfilter.c)
target_link_libraries(dbfwfilter log_manager utils query_classifier)
install(TARGETS dbfwfilter DESTINATION modules)

add_library(namedserverfilter SHARED namedserverfilter.c)
target_link_libraries(namedserverfilter log_manager utils)
install(TARGETS namedserverfilter DESTINATION modules)

if(BUILD_SLAVELAG)
  add_library(slavelag SHARED slavelag.c)
  target_link_libraries(slavelag log_manager utils query_classifier)
  install(TARGETS slavelag DESTINATION modules)
endif()

if(BUILD_TOOLS)
  add_executable(ruleparser dbfwfilter.c)
  target_compile_definitions(ruleparser PUBLIC "BUILD_RULE_PARSER")
  target_link_libraries(ruleparser  ${EMBEDDED_LIB} log_manager utils query_classifier fullcore)
  install(TARGETS ruleparser DESTINATION tools)
endif()

add_subdirectory(hint)

if(BUILD_TESTS)
  add_subdirectory(test)
endif()
