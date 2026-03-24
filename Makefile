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

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
