
#ifndef WASM_GFX_IMPORTS_H
#define WASM_GFX_IMPORTS_H

#include <dlfcn.h>
#include "SDL.h"
#include "gl.h"

#define WASM_GFX_IMPORTS \
	{ .name = "glGetError",                 .fn = gfx_glGetError }, \
	{ .name = "SDL_GL_SwapWindow",          .fn = gfx_SDL_GL_SwapWindow }, \
	{ .name = "SDL_GL_SetSwapInterval",     .fn = gfx_SDL_GL_SetSwapInterval }, \
	{ .name = "glGetShaderiv",              .fn = gfx_glGetShaderiv }, \
	{ .name = "glGetShaderInfoLog",         .fn = gfx_glGetShaderInfoLog }, \
	{ .name = "glGenFramebuffers",          .fn = gfx_glGenFramebuffers }, \
	{ .name = "glBindFramebuffer",          .fn = gfx_glBindFramebuffer }, \
	{ .name = "glGenTextures",              .fn = gfx_glGenTextures }, \
	{ .name = "glBindTexture",              .fn = gfx_glBindTexture }, \
	{ .name = "glTexImage2D",               .fn = gfx_glTexImage2D }, \
	{ .name = "glTexParameteri",            .fn = gfx_glTexParameteri }, \
	{ .name = "glFramebufferTexture2D",     .fn = gfx_glFramebufferTexture2D }, \
	{ .name = "glCheckFramebufferStatus",   .fn = gfx_glCheckFramebufferStatus }, \
	{ .name = "glDeleteFramebuffers",       .fn = gfx_glDeleteFramebuffers }, \
	{ .name = "SDL_Init",                   .fn = gfx_SDL_Init }, \
	{ .name = "SDL_CreateWindow",           .fn = gfx_SDL_CreateWindow }, \
	{ .name = "SDL_GL_CreateContext",       .fn = gfx_SDL_GL_CreateContext }, \
	{ .name = "SDL_SetRelativeMouseMode",   .fn = gfx_SDL_SetRelativeMouseMode }, \
	{ .name = "glDrawElements",             .fn = gfx_glDrawElements }, \
	{ .name = "glDrawArrays",               .fn = gfx_glDrawArrays }, \
	{ .name = "SDL_GetPerformanceFrequency",.fn = gfx_SDL_GetPerformanceFrequency }, \
	{ .name = "SDL_GetPerformanceCounter",  .fn = gfx_SDL_GetPerformanceCounter }, \
	{ .name = "SDL_PollEvent",              .fn = gfx_SDL_PollEvent }, \
	{ .name = "SDL_Quit",                   .fn = gfx_SDL_Quit }, \
	{ .name = "SDL_GetModState",            .fn = gfx_SDL_GetModState }, \
	{ .name = "SDL_GetKeyboardState",       .fn = gfx_SDL_GetKeyboardState }, \
	{ .name = "glEnable",                   .fn = gfx_glEnable }, \
	{ .name = "glCullFace",                 .fn = gfx_glCullFace }, \
	{ .name = "glClearColor",               .fn = gfx_glClearColor }, \
	{ .name = "glClear",                    .fn = gfx_glClear }, \
	{ .name = "glDisable",                  .fn = gfx_glDisable }, \
	{ .name = "glUseProgram",               .fn = gfx_glUseProgram }, \
	{ .name = "glPolygonMode",              .fn = gfx_glPolygonMode }, \
	{ .name = "glUniform3f",                .fn = gfx_glUniform3f }, \
	{ .name = "glUniform1i",                .fn = gfx_glUniform1i }, \
	{ .name = "glUniform1f",                .fn = gfx_glUniform1f }, \
	{ .name = "glUniformMatrix4fv",         .fn = gfx_glUniformMatrix4fv }, \
	{ .name = "glCreateShader",             .fn = gfx_glCreateShader }, \
	{ .name = "glShaderSource",             .fn = gfx_glShaderSource }, \
	{ .name = "glCompileShader",            .fn = gfx_glCompileShader }, \
	{ .name = "glDeleteShader",             .fn = gfx_glDeleteShader }, \
	{ .name = "glGetAttribLocation",        .fn = gfx_glGetAttribLocation }, \
	{ .name = "glGetUniformLocation",       .fn = gfx_glGetUniformLocation }, \
	{ .name = "glCreateProgram",            .fn = gfx_glCreateProgram }, \
	{ .name = "glAttachShader",             .fn = gfx_glAttachShader }, \
	{ .name = "glLinkProgram",              .fn = gfx_glLinkProgram }, \
	{ .name = "glGetProgramiv",             .fn = gfx_glGetProgramiv }, \
	{ .name = "glDeleteProgram",            .fn = gfx_glDeleteProgram }, \
	{ .name = "glDepthFunc",                .fn = gfx_glDepthFunc }, \
	{ .name = "glDepthMask",                .fn = gfx_glDepthMask }, \
	{ .name = "glUniform2f",                .fn = gfx_glUniform2f }, \
	{ .name = "glDeleteTextures",           .fn = gfx_glDeleteTextures }, \
	{ .name = "glDeleteRenderbuffers",      .fn = gfx_glDeleteRenderbuffers }, \
	{ .name = "SDL_GetTicks",               .fn = gfx_SDL_GetTicks }, \
	{ .name = "glGenBuffers",               .fn = gfx_glGenBuffers }, \
	{ .name = "glBindBuffer",               .fn = gfx_glBindBuffer }, \
	{ .name = "glBufferData",               .fn = gfx_glBufferData }, \
	{ .name = "glEnableVertexAttribArray",  .fn = gfx_glEnableVertexAttribArray }, \
	{ .name = "glVertexAttribIPointer",     .fn = gfx_glVertexAttribIPointer }, \
	{ .name = "glVertexAttribPointer",      .fn = gfx_glVertexAttribPointer }, \
	{ .name = "glViewport",                 .fn = gfx_glViewport }, \
	{ .name = "glXGetProcAddressARB",       .fn = gfx_glXGetProcAddressARB },

#define IMPL_SINGLE_PARAM(name) \
static int gfx_##name(struct wasm_interp *interp) \
{ \
	struct val *params = NULL;\
	if (!get_params(interp, &params, 1) || params == NULL)\
		return interp_error(interp, "get params");\
	name(params[0].num.i32);\
	return 1;\
}

#define IMPL_TWO_INTS(name) \
static int gfx_##name(struct wasm_interp *interp) \
{ \
	struct val *params = NULL;\
	if (!get_params(interp, &params, 2) || params == NULL)\
		return interp_error(interp, "get params");\
	name(params[0].num.i32, params[1].num.i32);\
	return 1;\
}

static int gfx_glGetError(struct wasm_interp *interp)
{
	return stack_push_i32(interp, glGetError());
}

static int gfx_glGetShaderiv(struct wasm_interp *interp)
{
	struct val *params = NULL;
	int *ps;

	if (!get_params(interp, &params, 3) || params == NULL)
		return interp_error(interp, "get params");

	if (!mem_ptr_i32(interp, params[2].num.u32, &ps))
		return interp_error(interp, "glint params");

	debug("glGetShaderiv %d %d %d\n",
			params[0].num.u32,
			params[1].num.u32,
			params[2].num.u32);

	glGetShaderiv(params[0].num.u32, params[1].num.u32, ps);

	debug("glGetShaderiv ps %d\n", *ps);

	return 1;
}

static int gfx_glGetShaderInfoLog(struct wasm_interp *interp)
{
	struct val *params = NULL;
	const char *info_log;
	int *length;

	if (!get_params(interp, &params, 4) || params == NULL)
		return interp_error(interp, "get params");

	if (!mem_ptr_i32(interp, params[2].num.i32, &length))
		return interp_error(interp, "length mem ptr");

	if (!mem_ptr_str(interp, params[3].num.i32, &info_log))
		return interp_error(interp, "info log ptr");

	glGetShaderInfoLog(
		params[0].num.i32,
		params[1].num.i32,
		length,
		(char*)info_log);

	return 1;
}

static int gfx_glGenFramebuffers(struct wasm_interp *interp)
{
	struct val *params = NULL;
	u32 *ids;

	if (!get_params(interp, &params, 2) || params == NULL)
		return interp_error(interp, "get params");

	if (!mem_ptr_u32(interp, params[1].num.i32, &ids))
		return interp_error(interp, "ids");

	glGenFramebuffers(params[0].num.i32, ids);

	return 1;
}

static int gfx_glGenTextures(struct wasm_interp *interp)
{
	struct val *params = NULL;
	int *textures;

	if (!get_params(interp, &params, 2) || params == NULL)
		return interp_error(interp, "get params");

	if (!mem_ptr_i32(interp, params[1].num.i32, &textures))
		return interp_error(interp, "get textures");

	glGenTextures(params[0].num.i32, (u32*)textures);
	return 1;
}

static int gfx_glTexImage2D(struct wasm_interp *interp)
{
	struct val *params = NULL;
	int width, height, size;
	u8 *data = NULL;

	if (!get_params(interp, &params, 9) || params == NULL)
		return interp_error(interp, "get params");

	width = params[3].num.i32;
	height = params[4].num.i32;
	size = width * height; // TODO: fix size calc

	if (params[8].num.i32 && !(data = mem_ptr(interp, params[8].num.i32, size)))
		return interp_error(interp, "data");

	glTexImage2D(
		params[0].num.i32,
		params[1].num.i32,
		params[2].num.i32,
		width,
		height,
		params[5].num.i32,
		params[6].num.i32,
		params[7].num.i32,
		data);

	return 1;
}

static int gfx_glTexParameteri(struct wasm_interp *interp)
{
	struct val *params = NULL;
	if (!get_params(interp, &params, 3) || params == NULL)
		return interp_error(interp, "get params");
	glTexParameteri(
		params[0].num.i32,
		params[1].num.i32,
		params[2].num.i32);
	return 1;
}

static int gfx_glFramebufferTexture2D(struct wasm_interp *interp)
{
	struct val *params = NULL;
	if (!get_params(interp, &params, 5) || params == NULL)
		return interp_error(interp, "get params");
	glFramebufferTexture2D(
		params[0].num.i32,
		params[1].num.i32,
		params[2].num.i32,
		params[3].num.i32,
		params[4].num.i32
	);
	return 1;
}

static int gfx_glCheckFramebufferStatus(struct wasm_interp *interp)
{
	struct val *params = NULL;
	if (!get_params(interp, &params, 1) || params == NULL)
		return interp_error(interp, "get params");
	return stack_push_i32(interp,
			glCheckFramebufferStatus(params[0].num.i32));
}

static int gfx_glDeleteFramebuffers(struct wasm_interp *interp)
{
	struct val *params = NULL;
	u32 *buffers;

	if (!get_params(interp, &params, 2) || params == NULL)
		return interp_error(interp, "get params");

	if (!mem_ptr_u32(interp, params[1].num.i32, &buffers))
		return interp_error(interp, "buffers ptr");

	glDeleteFramebuffers(params[0].num.i32, buffers);

	return 1;
}

static int gfx_SDL_Init(struct wasm_interp *interp)
{
	struct val *flags;
	int res;
	if (!(flags = get_local(interp, 0)))
		return interp_error(interp, "flags arg");
	res = SDL_Init(flags->num.i32);
	return stack_push_i32(interp, res);
}

static SDL_Window *sdl_window = NULL;
static SDL_GLContext sdl_gl_ctx = 0;

static int gfx_SDL_CreateWindow(struct wasm_interp *interp)
{
	struct val *params = NULL;
	if (!get_params(interp, &params, 6) || params == NULL)
		return interp_error(interp, "get params");
	sdl_window = SDL_CreateWindow("protoverse window",
			params[1].num.i32,
			params[2].num.i32,
			params[3].num.i32,
			params[4].num.i32,
			params[5].num.u32);
	return stack_push_i32(interp, 1);
}

static int gfx_SDL_GL_SetSwapInterval(struct wasm_interp *interp)
{
	struct val *params = NULL;
	if (!get_params(interp, &params, 1) || params == NULL)
		return interp_error(interp, "get params");
	return stack_push_i32(interp,
			SDL_GL_SetSwapInterval(params[0].num.i32));
}

static int gfx_SDL_GL_SwapWindow(struct wasm_interp *interp)
{
	(void)interp;
	SDL_GL_SwapWindow(sdl_window);
	return 1;
}

static int gfx_SDL_GL_CreateContext(struct wasm_interp *interp)
{
	if (sdl_window == NULL)
		return interp_error(interp, "SDL_CreateWindow was not called");
	sdl_gl_ctx = SDL_GL_CreateContext(sdl_window);
	return stack_push_i32(interp, 1);
}

static int gfx_SDL_SetRelativeMouseMode(struct wasm_interp *interp)
{
	struct val *params = NULL;
	if (!get_params(interp, &params, 1) || params == NULL)
		return interp_error(interp, "get params");
	return stack_push_i32(interp,
			SDL_SetRelativeMouseMode(params[0].num.i32));
}

static int gfx_glDrawElements(struct wasm_interp *interp)
{
	struct val *params = NULL;
	u8 *indices = NULL;

	if (!get_params(interp, &params, 4) || params == NULL)
		return interp_error(interp, "get params");

	if (params[3].num.i32 && !(indices = mem_ptr(interp, params[3].num.i32,
						     params[1].num.i32)))
		return interp_error(interp, "indices");

	glDrawElements(
		params[0].num.i32,
		params[1].num.i32,
		params[2].num.i32,
		indices);
	return 1;
}

static int gfx_glDrawArrays(struct wasm_interp *interp)
{
	return interp_error(interp, "todo: implement gfx_glDrawArrays");
}

static int gfx_SDL_GetPerformanceFrequency(struct wasm_interp *interp)
{
	return stack_push_u64(interp, SDL_GetPerformanceFrequency());
}

static int gfx_SDL_GetPerformanceCounter(struct wasm_interp *interp)
{
	return stack_push_u64(interp, SDL_GetPerformanceCounter());
}

static int gfx_SDL_PollEvent(struct wasm_interp *interp)
{
	struct val *params = NULL;
	SDL_Event *ev;

	if (!get_params(interp, &params, 1) || params == NULL)
		return interp_error(interp, "get params");

	if (!(ev = (SDL_Event *)mem_ptr(interp, params[0].num.i32,
					sizeof(SDL_Event))))
		return interp_error(interp, "event");

	return stack_push_i32(interp, SDL_PollEvent(ev));
}

static int gfx_SDL_Quit(struct wasm_interp *interp)
{
	return interp_error(interp, "todo: implement gfx_SDL_Quit");
}

static int gfx_SDL_GetModState(struct wasm_interp *interp)
{
	return stack_push_i32(interp, SDL_GetModState());
}

static int gfx_SDL_GetKeyboardState(struct wasm_interp *interp)
{
	int *numkeys = NULL;
	struct val *params = NULL;
	u8 *dest;
	const unsigned char *host_keys;
	int nk;

	if (!get_params(interp, &params, 1) || params == NULL)
		return interp_error(interp, "get params");

	host_keys = SDL_GetKeyboardState(&nk);

	if (numkeys) {
		if (!mem_ptr_i32(interp, params[0].num.i32, &numkeys))
			return interp_error(interp, "numkeys mem ptr");
		*numkeys = nk;
	}

	dest = interp->memory.start +
		(active_pages(interp) * WASM_PAGE_SIZE - nk);

	if (dest < interp->memory.start)
		return interp_error(interp, "nowhere to store keyboard state");

	memcpy(dest, host_keys, nk);

	return stack_push_i32(interp, dest - interp->memory.start);
}

IMPL_SINGLE_PARAM(glEnable)
IMPL_SINGLE_PARAM(glDisable)
IMPL_SINGLE_PARAM(glClear)
IMPL_SINGLE_PARAM(glCullFace)
IMPL_SINGLE_PARAM(glCompileShader)
IMPL_SINGLE_PARAM(glDeleteShader)
IMPL_SINGLE_PARAM(glLinkProgram)
IMPL_SINGLE_PARAM(glDeleteProgram)
IMPL_SINGLE_PARAM(glUseProgram)
IMPL_SINGLE_PARAM(glEnableVertexAttribArray)
IMPL_SINGLE_PARAM(glDepthFunc)
IMPL_SINGLE_PARAM(glDepthMask)

IMPL_TWO_INTS(glAttachShader)
IMPL_TWO_INTS(glBindBuffer)
IMPL_TWO_INTS(glBindTexture)
IMPL_TWO_INTS(glBindFramebuffer)
IMPL_TWO_INTS(glUniform1i)
IMPL_TWO_INTS(glPolygonMode)

static int gfx_glClearColor(struct wasm_interp *interp)
{
	struct val *params = NULL;
	if (!get_params(interp, &params, 4) || params == NULL)
		return interp_error(interp, "get params");
	glClearColor(params[0].num.f32,
		     params[1].num.f32,
		     params[2].num.f32,
		     params[3].num.f32);
	return 1;
}

static int gfx_glUniform3f(struct wasm_interp *interp)
{
	struct val *params = NULL;
	if (!get_params(interp, &params, 4) || params == NULL)
		return interp_error(interp, "get params");

	glUniform3f(
		params[0].num.i32,
		params[1].num.f32,
		params[2].num.f32,
		params[3].num.f32);

	return 1;
}

static int gfx_glUniform1f(struct wasm_interp *interp)
{
	struct val *params = NULL;
	if (!get_params(interp, &params, 2) || params == NULL)
		return interp_error(interp, "get params");

	glUniform1f(
		params[0].num.i32,
		params[1].num.f32);

	return 1;
}

static int gfx_glUniformMatrix4fv(struct wasm_interp *interp)
{
	struct val *params = NULL;
	float *val;

	if (!get_params(interp, &params, 4) || params == NULL)
		return interp_error(interp, "get params");

	if (!mem_ptr_f32(interp, params[3].num.i32, &val))
		return interp_error(interp, "matrix");

	glUniformMatrix4fv(
		params[0].num.i32,
		params[1].num.i32,
		params[2].num.i32,
		val);

	return 1;
}

static int gfx_glCreateShader(struct wasm_interp *interp)
{
	struct val *params = NULL;
	if (!get_params(interp, &params, 1) || params == NULL)
		return interp_error(interp, "get params");
	return stack_push_i32(interp, glCreateShader(params[0].num.i32));
}

static int gfx_glShaderSource(struct wasm_interp *interp)
{
	struct val *params = NULL;
	const char *strs[1024];
	u32 lens_ptr, str_ptrs, str_ptr = 0, len, i, count;
	int *lens;

	if (!get_params(interp, &params, 4) || params == NULL)
		return interp_error(interp, "get params");

	count = params[1].num.i32;

	if (count >= ARRAY_SIZE(strs)) {
		return interp_error(interp, "too many shaders %d > %d",
				count, ARRAY_SIZE(strs));
	}

	str_ptrs = params[2].num.u32;
	lens_ptr = params[3].num.u32;
	lens = NULL;

	if (lens_ptr) {
		if (!read_mem_u32(interp, lens_ptr, &len))
			return interp_error(interp, "err reading len");

		if (!mem_ptr_i32(interp, lens_ptr, &lens))
			return interp_error(interp, "lens ptr");
	}

	for (i = 0; i < count; i++) {
		if (!read_mem_u32(interp, str_ptrs + (4*i), &str_ptr))
			return interp_error(interp, "err reading str_tr %d", i);

		if (lens_ptr && !read_mem_u32(interp, lens_ptr + (4*i), &len))
			return interp_error(interp, "err reading len %d", i);
		if (!mem_ptr_str(interp, str_ptr, &strs[i]))
			return interp_error(interp, "str ptr %d", i);
		debug("shader str %d: '%s' len %d\n", i, strs[i], len);
	}

	debug("glShaderSource count %d strs[0] '%s', lens %d\n",
			count, strs[0], lens ? lens[0] : (int)lens_ptr);

	glShaderSource(params[0].num.u32, count, strs, lens);
	return 1;
}

static int gfx_glGetAttribLocation(struct wasm_interp *interp)
{
	struct val *params = NULL;
	const char *name;

	if (!get_params(interp, &params, 2) || params == NULL)
		return interp_error(interp, "get params");

	if (!mem_ptr_str(interp, params[1].num.i32, &name))
		return interp_error(interp, "invalid name ptr");

	return stack_push_i32(interp,
			glGetAttribLocation(params[0].num.i32, name));
}

static int gfx_glGetUniformLocation(struct wasm_interp *interp)
{
	struct val *params = NULL;
	const char *name;

	if (!get_params(interp, &params, 2) || params == NULL)
		return interp_error(interp, "get params");

	if (!mem_ptr_str(interp, params[1].num.i32, &name))
		return interp_error(interp, "invalid name ptr");

	return stack_push_i32(interp,
			glGetUniformLocation(params[0].num.i32, name));
}

static int gfx_glCreateProgram(struct wasm_interp *interp)
{
	return stack_push_i32(interp, glCreateProgram());
}

static int gfx_glGetProgramiv(struct wasm_interp *interp)
{
	struct val *params = NULL;
	int *ps;

	if (!get_params(interp, &params, 3) || params == NULL)
		return interp_error(interp, "get params");

	if (!mem_ptr_i32(interp, params[2].num.i32, &ps))
		return interp_error(interp, "params mem addr");

	debug("glGetProgramiv %d %d %d\n",
			params[0].num.i32,
			params[1].num.i32,
			*ps);

	glGetProgramiv(params[0].num.i32, params[1].num.i32, ps);
	return 1;
}

static int gfx_glUniform2f(struct wasm_interp *interp)
{
	struct val *params = NULL;
	if (!get_params(interp, &params, 3) || params == NULL)
		return interp_error(interp, "get params");

	glUniform2f(
		params[0].num.i32,
		params[1].num.f32,
		params[2].num.f32);

	return 1;
}

static int gfx_glDeleteTextures(struct wasm_interp *interp)
{
	struct val *params = NULL;
	u32 *textures;

	if (!get_params(interp, &params, 2) || params == NULL)
		return interp_error(interp, "get params");

	if (!mem_ptr_u32(interp, params[1].num.i32, &textures))
		return interp_error(interp, "textures ptr");

	glDeleteTextures(params[0].num.i32, textures);

	return 1;
}

static int gfx_glDeleteRenderbuffers(struct wasm_interp *interp)
{
	struct val *params = NULL;
	u32 *buffers;

	if (!get_params(interp, &params, 2) || params == NULL)
		return interp_error(interp, "get params");

	if (!mem_ptr_u32(interp, params[1].num.i32, &buffers))
		return interp_error(interp, "buffers ptr");

	glDeleteRenderbuffers(params[0].num.i32, buffers);

	return 1;
}

static int gfx_SDL_GetTicks(struct wasm_interp *interp)
{
	return stack_push_i32(interp, SDL_GetTicks());
}

static int gfx_glGenBuffers(struct wasm_interp *interp)
{
	struct val *params = NULL;
	u32 *buffers;
	int n;

	if (!get_params(interp, &params, 2) || params == NULL)
		return interp_error(interp, "get params");

	n = params[0].num.i32;

	if (!mem_ptr_u32_arr(interp, params[1].num.i32, n, &buffers))
		return interp_error(interp, "gen buffers");

	glGenBuffers(params[0].num.i32, buffers);
	return 1;
}

static int gfx_glBufferData(struct wasm_interp *interp)
{
	struct val *params = NULL;
	int size, usage;
	u8 *data;

	if (!get_params(interp, &params, 4) || params == NULL)
		return interp_error(interp, "get params");

	size = params[1].num.i32;
	usage = params[3].num.i32;

	if (!(data = mem_ptr(interp, params[2].num.i32, size)))
		return interp_error(interp, "data");

	glBufferData(params[0].num.i32, size, data, usage);
	return 1;
}

static int gfx_glVertexAttribIPointer(struct wasm_interp *interp)
{
	return interp_error(interp, "todo: implement gfx_glVertexAttribIPointer");
}

static int gfx_glVertexAttribPointer(struct wasm_interp *interp)
{
	struct val *params = NULL;
	u8 *ptr = NULL;

	if (!get_params(interp, &params, 6) || params == NULL)
		return interp_error(interp, "get params");

	if (params[5].num.i32 != 0 &&
		!(ptr = mem_ptr(interp, params[5].num.i32, params[1].num.i32)))
		return interp_error(interp, "pointer");

	glVertexAttribPointer(
		params[0].num.i32,
		params[1].num.i32,
		params[2].num.i32,
		params[3].num.i32,
		params[4].num.i32,
		ptr);

	return 1;
}

static struct table_inst *find_fn_table(struct module_inst *inst)
{
	u32 i;

	for (i = 0; i < inst->num_tables; i++) {
		if (inst->tables[i].reftype == funcref)
			return &inst->tables[i];
	}
	return NULL;
}

static int find_table_ref(struct table_inst *table, u32 ind, u32 *out)
{
	u32 i;

	for (i = 0; i < table->num_refs; i++) {
		if (table->refs[i].addr == ind) {
			*out = i;
			return 1;
		}
	}

	return 0;
}


static int gfx_glXGetProcAddressARB(struct wasm_interp *interp)
{
	void *gl_handle;
	struct callframe *frame;
	struct table_inst *fn_table;
	u32 ref_ind;
	int builtin;

	const char *name;
	struct val *params = NULL;

	if (!get_params(interp, &params, 1) || params == NULL)
		return interp_error(interp, "get params");

	gl_handle = dlopen("libGL.so", RTLD_LAZY);
	if (!gl_handle)
		return interp_error(interp, "couldn't load libGL.so");

	if (!mem_ptr_str(interp, params[0].num.i32, &name))
		return interp_error(interp, "name");

	if (!(frame = top_callframes(&interp->callframes, 1)))
		return interp_error(interp, "no prev fn?");

	if (!(fn_table = find_fn_table(&interp->module_inst)))
		return interp_error(interp, "no fn table?");

	if (!find_table_ref(fn_table, frame->func->idx, &ref_ind)) {
		return interp_error(interp, "function %s:%d not found in table",
				get_function_name(interp->module, frame->func->idx),
				frame->func->idx);
	}

	/*
	if (!GalogenGetProcAddress(name))
		return interp_error(interp, "couldn't load '%s' function\n",
				name);
				*/

	if ((builtin = find_builtin(name)) == -1)
		return interp_error(interp,
				"couldn't find gfx builtin '%s'", name);

	fn_table->refs[ref_ind].addr = -builtin;

	return stack_push_i32(interp, ref_ind);
}

static int gfx_glViewport(struct wasm_interp *interp)
{
	struct val *params = NULL;

	if (!get_params(interp, &params, 4) || params == NULL)
		return interp_error(interp, "get params");

	glViewport(
		params[0].num.i32,
		params[1].num.i32,
		params[2].num.i32,
		params[3].num.i32);

	return 1;
}


#endif
