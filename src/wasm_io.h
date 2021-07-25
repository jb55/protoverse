
#ifndef _PROTOVERSE_WASM_IO_
#define _PROTOVERSE_WASM_IO_

#define WASM_IO_IMPORTS \
	{ .name = "fopen",             .fn = protoverse_fopen }, \
	{ .name = "feof",              .fn = protoverse_feof }, \
	{ .name = "stat",              .fn = protoverse_stat }, \
	{ .name = "fseek",             .fn = protoverse_fseek }, \
	{ .name = "ftell",             .fn = protoverse_ftell }, \
	{ .name = "rand",              .fn = protoverse_rand }, \
	{ .name = "srand",             .fn = protoverse_srand }, \
	{ .name = "fflush",            .fn = protoverse_fflush }, \
	{ .name = "fread",             .fn = protoverse_fread }, \
	{ .name = "fclose",            .fn = protoverse_fclose }, \

static int find_open_file_ind(struct open_files *files, u32 ind)
{
	ind -= 1337;

	//debug("ind %d >= files->num_files %d\n", ind, files->num_files);

	// TODO: set guest errno?
	if (ind >= files->num_files)
		return -1;

	return ind;
}

static FILE *find_open_file(struct open_files *files, int ind)
{
	if ((ind = find_open_file_ind(files, ind)) == -1)
		return NULL;
	return files->files[ind];
}

static int protoverse_srand(struct wasm_interp *interp)
{
	struct val *params = NULL;
	if (!get_params(interp, &params, 1))
		return interp_error(interp, "srand param");

	srand(params[0].num.i32);
	return 1;
}

static int protoverse_rand(struct wasm_interp *interp)
{
	return stack_push_i32(interp, rand());
}

static int protoverse_feof(struct wasm_interp *interp)
{
	struct val *params = NULL;
	FILE *stream;

	if (!get_params(interp, &params, 1))
		return interp_error(interp, "fread params");

	if (!(stream = find_open_file(&interp->open_files, params[0].num.i32))) {
		debug("feof: no FILE* ??\n");
		return stack_push_i32(interp, 0);
	}

	return stack_push_i32(interp, feof(stream));
}

static int protoverse_stat(struct wasm_interp *interp)
{
	struct val *params = NULL;
	const char *pathname;
	struct stat st;

	if (!get_params(interp, &params, 2))
		return interp_error(interp, "fread params");

	pathname = (const char *)interp->memory.start + params[0].num.u32;

	if (!read_mem(interp, params[1].num.u32, sizeof(st), &st))
		return interp_error(interp, "read stat buf");

	return stack_push_i32(interp, stat(pathname, &st));
}

static int protoverse_fread(struct wasm_interp *interp)
{
	struct val *params = NULL;
	FILE *stream;
	size_t res;
	u8 *ptr;
	u32 size;

	if (!get_params(interp, &params, 4))
		return interp_error(interp, "fread params");

	if (!(stream = find_open_file(&interp->open_files, params[3].num.i32))) {
		debug("fread: no FILE* ??\n");
		return stack_push_i32(interp, 0);
	}

	ptr = interp->memory.start + params[0].num.i32;
	size = params[1].num.u32 * params[2].num.u32;

	if (ptr + size >= interp->memory.p)
		return interp_error(interp, "fread oob");

	res = fread(ptr, params[1].num.i32, params[2].num.i32, stream);

	return stack_push_i32(interp, res);
}

static int protoverse_fclose(struct wasm_interp *interp)
{
	struct val *params = NULL;
	int ind, res;

	if (!get_params(interp, &params, 1))
		return interp_error(interp, "fclose params");

	if ((ind = find_open_file_ind(&interp->open_files,
				       params[0].num.i32)) == -1) {
		return stack_push_i32(interp, EOF);
	}

	if ((res = fclose(interp->open_files.files[ind])) == EOF)
		return stack_push_i32(interp, EOF);

	return stack_push_i32(interp, res);
}

static int protoverse_fflush(struct wasm_interp *interp)
{
	struct val *params = NULL;
	FILE *stream;

	if (!get_params(interp, &params, 1))
		return interp_error(interp, "ftell params");

	if (!(stream = find_open_file(&interp->open_files, params[0].num.i32)))
		return stack_push_i32(interp, EOF);

	return stack_push_i32(interp, fflush(stream));
}

static int protoverse_ftell(struct wasm_interp *interp)
{

	struct val *params = NULL;
	FILE *stream;

	if (!get_params(interp, &params, 1))
		return interp_error(interp, "ftell params");

	if (!(stream = find_open_file(&interp->open_files, params[0].num.i32)))
		return stack_push_i32(interp, -1);

	return stack_push_i32(interp, ftell(stream));
}

static int protoverse_fseek(struct wasm_interp *interp)
{
	struct val *params = NULL;
	FILE *stream;

	if (!get_params(interp, &params, 3))
		return interp_error(interp, "fseek params");

	if (!(stream = find_open_file(&interp->open_files, params[0].num.i32)))
		return stack_push_i32(interp, -1);

	return stack_push_i32(interp,
			fseek(stream, params[1].num.i32, params[2].num.i32));
}

static int protoverse_fopen(struct wasm_interp *interp)
{
	struct val *params = NULL;
	const char *filename, *mode;
	int i;
	FILE *res;

	if (!get_params(interp, &params, 2))
		return interp_error(interp, "fopen params");

	filename = (const char*)(interp->memory.start + params[0].num.i32);
	mode = (const char*)(interp->memory.start + params[1].num.i32);

	if (interp->open_files.num_files + 1 >
			ARRAY_SIZE(interp->open_files.files)) {
		return interp_error(interp, "too many open files (%d)",
			interp->open_files.num_files);
	}

	//debug("got args fopen args '%s', '%s'\n", filename, mode);
	if (!(res = fopen(filename, mode))) {
		return stack_push_i32(interp, 0);
	}

	i = interp->open_files.num_files++;
	interp->open_files.files[i] = res;

	return stack_push_i32(interp, 1337+i);
}

#endif

