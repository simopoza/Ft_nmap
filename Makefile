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

.PHONY: test
test: test-args
	@mkdir -p bin
	$(CC) $(CFLAGS) src/args.c tests/test_args_negative.c -o bin/test_args_negative
	@echo "Running all tests..."
	./bin/test_args; rc1=$$?; \
	./bin/test_args_negative; rc2=$$?; \
	TOTAL=2; \
	FAILED=0; \
	if [ $$rc1 -ne 0 ]; then FAILED=$$((FAILED+1)); fi; \
	if [ $$rc2 -ne 0 ]; then FAILED=$$((FAILED+1)); fi; \
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
