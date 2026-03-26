NAME = ft_nmap
CC = gcc
CFLAGS = -Wall -Wextra -Werror -I./includes

SRC_DIR = src
OBJ_DIR = obj

SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/args.c $(SRC_DIR)/ports.c $(SRC_DIR)/scan.c $(SRC_DIR)/resolve.c $(SRC_DIR)/packet.c $(SRC_DIR)/pcap.c
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

LIBS = -lpcap -lpthread

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME) $(LIBS)

.PHONY: test-args
test-args: $(NAME)
	@mkdir -p bin
	$(CC) $(CFLAGS) src/args.c tests/test_args.c -o bin/test_args
	@echo "Running args unit test..."
	./bin/test_args

.PHONY: test-ports
test-ports: $(NAME)
	@mkdir -p bin
	$(CC) $(CFLAGS) src/ports.c tests/test_ports.c -o bin/test_ports
	@echo "Running ports unit test..."
	./bin/test_ports

.PHONY: test-resolve
test-resolve: $(NAME)
	@mkdir -p bin
	$(CC) $(CFLAGS) src/resolve.c tests/test_resolve.c -o bin/test_resolve
	@echo "Running resolve unit test..."
	./bin/test_resolve

.PHONY: test-scan-tcp
test-scan-tcp: $(NAME)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(SRC_DIR)/args.c $(SRC_DIR)/ports.c $(SRC_DIR)/scan.c $(SRC_DIR)/resolve.c $(SRC_DIR)/packet.c $(SRC_DIR)/pcap.c tests/test_scan_tcp_connect.c -o bin/test_scan_tcp_connect $(LIBS)
	@echo "Running tcp connect scan integration test..."
	./bin/test_scan_tcp_connect

.PHONY: test-send-udp
test-send-udp: $(NAME)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(SRC_DIR)/packet.c $(SRC_DIR)/pcap.c tests/test_send_udp_probe.c -o bin/test_send_udp_probe $(LIBS)
	@echo "Running udp probe send integration test..."
	./bin/test_send_udp_probe

.PHONY: test-scan-each
test-scan-each: $(NAME)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(SRC_DIR)/args.c $(SRC_DIR)/ports.c $(SRC_DIR)/scan.c $(SRC_DIR)/resolve.c $(SRC_DIR)/packet.c $(SRC_DIR)/pcap.c tests/test_scan_each_flag.c -o bin/test_scan_each_flag $(LIBS)
	@echo "Running scan-each-flag integration test..."
	./bin/test_scan_each_flag

.PHONY: test-file-input
test-file-input: $(NAME)
	@mkdir -p bin
	$(CC) $(CFLAGS) src/args.c tests/test_file_input.c -o bin/test_file_input
	@echo "Running file input parse test..."
	./bin/test_file_input

.PHONY: test

test: test-args test-ports test-resolve test-scan-tcp test-send-udp test-scan-each test-file-input
	@mkdir -p bin
	$(CC) $(CFLAGS) src/args.c tests/test_args_negative.c -o bin/test_args_negative
	@echo "Running all tests..."
	./bin/test_args; rc1=$$?; \
	./bin/test_args_negative; rc2=$$?; \
	./bin/test_ports; rc3=$$?; \
	./bin/test_resolve; rc4=$$?; \
	./bin/test_scan_tcp_connect; rc5=$$?; \
	./bin/test_send_udp_probe; rc6=$$?; \
	./bin/test_scan_each_flag; rc7=$$?; \
	./bin/test_file_input; rc8=$$?; \
	TOTAL=8; \
	FAILED=0; \
	if [ $$rc1 -ne 0 ]; then FAILED=$$((FAILED+1)); fi; \
	if [ $$rc2 -ne 0 ]; then FAILED=$$((FAILED+1)); fi; \
	if [ $$rc3 -ne 0 ]; then FAILED=$$((FAILED+1)); fi; \
	if [ $$rc4 -ne 0 ]; then FAILED=$$((FAILED+1)); fi; \
	if [ $$rc5 -ne 0 ]; then FAILED=$$((FAILED+1)); fi; \
	if [ $$rc6 -ne 0 ]; then FAILED=$$((FAILED+1)); fi; \
	if [ $$rc7 -ne 0 ]; then FAILED=$$((FAILED+1)); fi; \
	if [ $$rc8 -ne 0 ]; then FAILED=$$((FAILED+1)); fi; \
	PASSED=$$((TOTAL-FAILED)); \
	echo "Summary: $$PASSED passed, $$FAILED failed out of $$TOTAL"; \
	if [ $$FAILED -ne 0 ]; then exit 2; fi

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
